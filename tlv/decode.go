package tlv

import (
	"errors"
	"io"
	"math"

	"codello.dev/asn1"
	"codello.dev/asn1/internal/vlq"
)

//region Value

// Value represents a primitive TLV value. It implements [io.Reader] among
// others. At the end of the primitive value, Value returns [io.EOF]. Note that
// this only indicates the end of a single value, not the end of the
// corresponding [Decoder] stream. If the underlying reader returns [io.EOF]
// before the value has been read completely, [io.ErrUnexpectedEOF] is returned.
//
// Errors from the underlying reader may be wrapped before being returned.
type Value struct {
	d *Decoder
	n int // remaining number of bytes
}

// Len returns the number of bytes in the unread portion of the value.
func (v *Value) Len() int {
	if v.n < 0 {
		panic("illegal use of Value after ReadHeader()")
	}
	return v.n
}

// Read implements [io.Reader].
func (v *Value) Read(p []byte) (int, error) {
	if v.Len() == 0 {
		return 0, io.EOF
	}
	if len(p) > v.Len() {
		p = p[0:v.Len()]
	}
	n, err := v.d.br.Read(p)
	v.n -= n
	if v.Len() > 0 {
		// if the underlying reader returns io.EOF with data and v.Len() == 0
		// we can pass through the EOF.
		err = noEOF(err)
	}
	return n, err
}

// ReadByte implements [io.ByteReader].
func (v *Value) ReadByte() (b byte, err error) {
	if v.Len() == 0 {
		return 0, io.EOF
	}
	b, err = v.d.br.ReadByte()
	if err != nil {
		return 0, noEOF(err)
	}
	v.n--
	return b, nil
}

// Discard discards up to n bytes from v. It returns the number of bytes
// discarded. An error is returned iff discarded < n.
//
// If the underlying reader of r implements its own Discard method it will be
// used for more efficient discarding.
func (v *Value) Discard(n int) (discarded int, err error) {
	if n == 0 {
		return
	}

	discard := MinLength(n, v.Len())
	switch rd := v.d.br.(type) {
	case interface{ Discard(int) (int, error) }:
		discarded, err = rd.Discard(discard)
	default:
		var d int64
		d, err = io.CopyN(io.Discard, rd, int64(discard))
		discarded = int(d)
	}

	if n > v.Len() && err == nil {
		err = io.EOF
	} else if n < v.Len() {
		err = noEOF(err)
	}
	v.n -= discarded
	return discarded, err
}

//endregion

//region Decoder

// Decoder is a streaming decoder for the TLV format used by ASN.1 encoding
// rules such as BER, DER or CER. It is used to read a stream of top-level
// tag-length-value (TLV) constructs.
//
// Decoder can be used in presence of transient errors from the underlying
// reader. If an error occurs, the decoder is - in effect - reset to the state
// before the last ReadHeader call.
type Decoder struct {
	state
	br interface {
		io.Reader
		io.ByteReader
	}
	buf bufferedReader // internal buffering
	val *Value

	baseOffset int64 // beginning of next TLV or value
	peekOffset int   // relative to baseOffset

	// peekBuf stores the bytes read during the last ReadHeader operation so we can
	// recover from transient I/O errors. The maximum number of bytes for a valid
	// header is:
	//   - 1 identifier byte
	//   - 2 bytes for the long-form tag (more would be too large or not minimally encoded)
	//   - 1 byte for the number of length bytes
	//   - up to 8 length bytes (more would overflow an int)
	// We add 2 extra bytes for "integer too large" bytes and for padding.
	//
	// peekAt indicates the next read/write position in peekBuf and peekLen the
	// number of valid bytes in peekBuf. peekOffset is the number of bytes read
	// during the last ReadHeader call. This is equal to peekLen unless the length
	// bytes have leading zeros, in which case the leading zeros will not be added
	// to peekBuf or peekLen.

	peekBuf [14]byte
	peekAt  int8
	peekLen int8
}

// NewDecoder creates a new Decoder reading from r. If r does not implement
// [io.ByteReader], Decoder will do its own buffering. The buffering mechanism
// of Decoder attempts to buffer at most the number of bytes that belong to the
// current top-level TLV. However, if a top-level TLV uses the indefinite length
// format, the Decoder may buffer past the end of the value.
func NewDecoder(r io.Reader) *Decoder {
	d := new(Decoder)
	d.Reset(r)
	return d
}

// Reset resets the state of d to read from r. See [NewDecoder] for details.
//
// Reset reuses the internal buffer of d which may save some allocations
// compared to [NewDecoder].
func (d *Decoder) Reset(r io.Reader) {
	d.state.reset()

	if br, ok := r.(interface {
		io.Reader
		io.ByteReader
	}); ok {
		// allow previous reader to be garbage-collected, but keep the allocated buffer
		d.buf.Reset(nil)
		d.br = br
	} else {
		d.buf.Reset(r)
		d.br = &d.buf
	}
	d.val = nil

	d.baseOffset = 0
	d.peekOffset = 0
	d.peekAt = 0
	d.peekLen = 0
}

// ReadHeader reads the next TLV header from the input. At the end of
// constructed TLVs a Header with [TagEndOfContents] will be returned (for both
// definite and indefinite-length encodings). If an error occurs during decoding
// the TLV header, or it is detected that the TLV structure is invalid, an error
// is returned.
//
// The second return value is a non-nil [Value] iff the decoded Header indicates
// the use of the primitive encoding. The Value can be used to read the contents
// of the primitive TLV. The returned Value is only valid until the next call of
// [Decoder.ReadHeader]. Any unread bytes in Value will be discarded.
//
// ReadHeader can be used in presence of transient errors. If the underlying
// reader returns an error during the read operation, ReadHeader will return
// that error (potentially wrapped). If errors in the underlying reader are
// non-fatal, you can retry ReadHeader to resume the previous, erroneous call.
func (d *Decoder) ReadHeader() (Header, *Value, error) {
	d.peekAt = 0
	h, err := d.readHeader()
	if err != nil {
		if _, ok := err.(*ioError); err == io.EOF || ok {
			return h, nil, err
		}
		sErr := &SyntaxError{ByteOffset: d.baseOffset, Header: d.curr.Header, Err: err}
		//goland:noinspection GoDirectComparisonOfErrors
		if err == io.ErrUnexpectedEOF {
			sErr.ByteOffset = d.InputOffset()
		}
		return h, nil, sErr
	}
	// successful parse, reset peek buffer
	d.baseOffset += int64(d.peekOffset)
	d.peekLen = 0
	d.peekOffset = 0

	// adjust buffering
	switch d.StackDepth() {
	case 1: // we have just read the start of a top-level element
		d.buf.SetLimit(d.curr.Length)
	case 0: // we have just read the end of a top-level element
		d.buf.SetLimit(0)
	}
	if d.curr.Constructed {
		return h, nil, nil
	}
	d.val = &Value{d, d.curr.Remaining()}
	return h, d.val, nil
}

// readHeader decodes a TLV header from d. If decoding fails or an invalid TLV
// structure is detected, an error is returned.
func (d *Decoder) readHeader() (Header, error) {
	if !d.curr.Constructed {
		// discard the (rest of the) primitive element
		if err := d.discard(); err != nil {
			return Header{}, err
		}
	}
	if d.curr.Remaining() == 0 {
		d.state.pop()
		return Header{Tag: TagEndOfContents}, nil
	}

	h, err := d.decodeHeader()
	if err != nil {
		if !d.root() {
			err = noEOF(err)
		}
		return h, err
	}
	if h == (Header{}) && !d.root() && d.curr.Header.Length == LengthIndefinite {
		// The end-of-contents marker is 0x0000, which coincides with the empty
		// header.
		d.state.pop()
		return h, nil
	}
	if h == (Header{}) {
		err = errUnexpectedEOC
	} else if h.Tag == TagEndOfContents {
		// enc-of-contents is a reserved tag
		err = errInvalidEOC
	} else if !h.Constructed && h.Length == LengthIndefinite {
		err = errors.New("indefinite-length primitive element")
	} else if h.Length != LengthIndefinite && uint(h.Length) > uint(d.curr.Remaining()) {
		// uint conversion takes care of indefinite length
		err = errors.New("element exceeds parent")
	} else {
		d.state.push(h)
	}
	return h, err
}

// decodeHeader decodes a TLV header from d. If the encoded TLV header is
// invalid, or an I/O error occurs, an error is returned. An error is also
// returned if the header is syntactically valid but cannot be represented by
// the [Header] type.
func (d *Decoder) decodeHeader() (h Header, err error) {
	b, err := d.readByte()
	if err != nil {
		return Header{}, err
	}
	h = Header{
		Tag:         asn1.Class(b>>6)<<14 | asn1.Tag(b&0x1f),
		Constructed: b&0x20 == 0x20,
	}

	// If the bottom five bits are set, then the tag number is actually VLQ-encoded
	if b&0x1f == 0x1f {
		var n uint16
		n, err = vlq.ReadMinimal[uint16](byteReaderFunc(d.readByte))
		if err != nil {
			return h, noEOF(err)
		}

		h.Tag = h.Tag.Class() | (asn1.Tag(n) &^ (0b11 << 14))
		if n > asn1.MaxTag {
			return h, errors.New("tag number too large")
		}
	}

	if b, err = d.readByte(); err != nil {
		return h, noEOF(err)
	}
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		h.Length = int(b & 0x7f)
	} else if b == 0x80 {
		h.Length = LengthIndefinite
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		for numBytes := int(b & 0x7f); numBytes > 0; numBytes-- {
			if b, err = d.readByte(); err != nil {
				return h, noEOF(err)
			}
			if h.Length > math.MaxInt>>8 {
				// We can't shift h.length up without overflowing.
				return h, errors.New("length too large")
			}
			h.Length = h.Length<<8 | int(b)

			if h.Length == 0 {
				// an actual read (no from d.peekBuf) returned a leading zero
				// we do not store those in d.peekBuf
				d.peekAt--
				d.peekLen--
			}
		}
		if h == (Header{}) {
			return h, errInvalidEOC
		}
	}
	return h, nil
}

// readByte reads a single byte from the underlying reader of d. If d.peekLen is
// positive, reads are made from d.peekBuf first. If d.peekLen is negative, no
// data is read at all and an error is returned.
//
// Reads from the underlying reader are stored in d.peekBuf to enable the retry
// mechanism for transient errors.
func (d *Decoder) readByte() (b byte, err error) {
	if d.curr.Remaining() == 0 {
		return 0, errTruncated
	}
	if d.val != nil {
		// We are either inside of a primitive element or we have begun discarding the
		// current element. We cannot read a header here.
		return 0, errors.New("invalid state")
	}

	if d.peekAt < d.peekLen {
		b = d.peekBuf[d.peekAt]
	} else if b, err = d.br.ReadByte(); err == nil {
		d.peekBuf[d.peekAt] = b
		d.peekLen++
		d.peekOffset++
		d.curr.Offset++
	} else if err != io.EOF {
		return 0, &ioError{"read", err}
	} else {
		return 0, err
	}

	d.peekAt++
	return b, nil
}

// discard discards the remainder of the current element without validating the
// TLV syntax and removes it from the stack of d.
//
// The number of bytes to be discarded is determined by the length indicated by
// the preceding TLV headers. If the indefinite-length format is used, the
// length is determined by the parent TLV. If no length can be determined, an
// error is returned.
//
// When discard returns an error, d is left in an invalid state where the start
// of the next TLV cannot be determined. In this state no further reads are
// possible. Similarly to [Decoder.ReadHeader] it is possible to retry the
// discard method until a nil-error is returned. A nil-error indicates a valid
// state of d.
func (d *Decoder) discard() (err error) {
	if d.state.root() {
		return errors.New("cannot discard root element")
	}
	if d.curr.Length == LengthIndefinite {
		return errors.New("cannot discard indefinite number of bytes")
	}
	if d.val == nil {
		// interpret the current TLV as primitive to discard it
		d.val = &Value{d, d.curr.Remaining()}
	}
	if _, err = d.val.Discard(d.val.Len()); err != nil {
		return noEOF(err)
	}
	d.val.n = -1
	d.val = nil
	d.baseOffset += int64(d.peekOffset + d.curr.Remaining())
	d.peekOffset = 0
	d.curr.Offset += d.curr.Remaining()
	d.peekLen = 0

	// We have successfully discarded the element. The next byte is the start of the
	// next sibling TLV to the discarded one.
	d.state.pop()
	return nil
}

// Skip reads the remainder of the value of the current element If the current
// element uses the primitive encoding, only that element is skipped. If the
// current element is constructed, everything until the matching end-of-contents
// is skipped.
//
// If at any point an error is encountered, the skipping will be stopped and the
// error returned.
func (d *Decoder) Skip() (err error) {
	if !d.curr.Constructed {
		return d.discard()
	}
	depth := d.StackDepth()
	for d.StackDepth() >= depth && err == nil {
		_, _, err = d.ReadHeader()
	}
	return err
}

// InputOffset returns the current input byte offset. The number of bytes
// actually read from the underlying [io.Reader] may be more than this offset
// due to internal buffering effects.
//
//   - If the current TLV uses the primitive encoding, it gives the number of
//     bytes that have been read from the input, including any bytes read from the
//     current value.
//   - If the current TLV uses the constructed encoding, it gives the location of
//     the first byte of the next TLV header in the input.
func (d *Decoder) InputOffset() int64 {
	if d.val != nil {
		// this never happens if d.curr.Length is indefinite
		return d.baseOffset + int64(d.curr.Length-d.val.Len())
	}
	return d.baseOffset
}

// StackDepth returns the number of nested constructed TLVs of the current
// location of d. Each level represents a constructed TLV. It is incremented
// whenever a constructed TLV is encountered and decremented whenever a
// constructed TLV ends. The depth is zero-indexed, where zero represents the
// (virtual) top-level TLV.
func (d *Decoder) StackDepth() int { return len(d.stack) }

// StackIndex returns information about the specified stack level. It must be a
// number between 0 and [Decoder.StackDepth], inclusive.
//
// The TLV header at level 0 represents the top level and is not present in the
// input data. The top-level TLV header is a constructed, indefinite-length
// element with tag 0.
func (d *Decoder) StackIndex(i int) Header {
	if i == len(d.stack) {
		return d.curr.Header
	}
	return d.stack[i].Header
}

//endregion
