package tlv

import (
	"errors"
	"io"
	"math"

	"codello.dev/asn1"
	"codello.dev/asn1/internal/vlq"
)

//region valueReader

// valueReader represents a primitive TLV value. It implements [io.Reader] among
// others. At the end of the primitive value, valueReader returns [io.EOF]. Note
// that this only indicates the end of a single value, not the end of the
// corresponding [Decoder] stream. If the underlying reader returns [io.EOF]
// before the value has been read completely, [io.ErrUnexpectedEOF] is returned.
//
// Errors from the underlying reader may be wrapped before being returned.
type valueReader struct {
	d *Decoder
	n int // remaining number of bytes
}

// isValid indicates whether v is able to read more bytes.
func (v *valueReader) isValid() bool {
	return v.d != nil
}

// Len returns the number of bytes in the unread portion of the value.
func (v *valueReader) Len() int {
	return v.n
}

// Read implements [io.Reader].
func (v *valueReader) Read(p []byte) (int, error) {
	if v.d == nil {
		return 0, errClosed
	}
	if v.Len() == 0 {
		return 0, io.EOF
	}
	if len(p) > v.Len() {
		p = p[0:v.Len()]
	}
	n, err := v.d.br.Read(p)
	v.n -= n
	if err != nil && err != io.EOF {
		err = &ioError{"read", err}
	}
	if v.n == 0 {
		// if the underlying reader returns io.EOF with data and v.Len() == 0
		// we can pass through the EOF.
		return n, err
	}
	return n, noEOF(err)
}

// ReadByte implements [io.ByteReader].
func (v *valueReader) ReadByte() (b byte, err error) {
	if v.d == nil {
		return 0, errClosed
	}
	if v.Len() == 0 {
		return 0, io.EOF
	}
	b, err = v.d.br.ReadByte()
	if err != nil {
		if err == io.EOF {
			return 0, io.ErrUnexpectedEOF
		} else {
			return 0, &ioError{"read", err}
		}
	}
	v.n--
	return b, nil
}

// Discard discards up to n bytes from v. It returns the number of bytes
// discarded. An error is returned iff discarded < n.
//
// If the underlying reader of r implements its own Discard method it will be
// used for more efficient discarding.
func (v *valueReader) Discard(n int) (discarded int, err error) {
	if n < 0 {
		return 0, errors.New("tlv: negative count")
	}
	if v.d == nil {
		return 0, errClosed
	}

	l := v.Len()
	discard := min(n, l)
	if discard > 0 {
		switch rd := v.d.br.(type) {
		case interface{ Discard(int) (int, error) }:
			discarded, err = rd.Discard(discard)
		default:
			var d int64
			d, err = io.CopyN(io.Discard, rd, int64(discard))
			discarded = int(d)
		}
		v.n -= discarded
	}

	if n > l && err == nil {
		err = io.EOF
	} else if n < l {
		err = noEOF(err)
	}
	if err != nil && err != io.EOF {
		err = &ioError{"read", err}
	}
	return discarded, err
}

// Close discards any remaining bytes in the unread portion of v. If v has been
// read to EOF calling Close will never return an error.
func (v *valueReader) Close() error {
	if v.d == nil {
		return errClosed
	} else if _, err := v.Discard(v.Len()); err != nil {
		return err
	}
	v.d.valueDone()
	v.d = nil
	return nil
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
	val valueReader    // reused, saves allocations

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
	// number of valid bytes in peekBuf. peekBytes is the number of bytes read
	// during the last ReadHeader call. This is equal to peekLen unless the length
	// bytes have leading zeros, in which case the leading zeros will not be added
	// to peekBuf or peekLen.

	peekBuf   [14]byte
	peekAt    int8
	peekLen   int8
	peekBytes int // relative to state.offset
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
	d.val.d = nil

	d.peekBytes = 0
	d.peekAt = 0
	d.peekLen = 0
}

// ReadHeader reads the next TLV header from the input. At the end of
// constructed TLVs a Header with [TagEndOfContents] will be returned (for both
// definite and indefinite-length encodings). If an error occurs during decoding
// the TLV header, or it is detected that the TLV structure is invalid, an error
// is returned.
//
// The second return value is non-nil iff the decoded Header indicates the use
// of the primitive encoding. The [io.ReadCloser] can be used to read the
// contents of the primitive TLV. It also implements [io.ByteReader].
// [io.Closer.Close] must be called before the next call of [Decoder.ReadHeader]
// or [Decoder.PeekHeader].
//
// ReadHeader can be used in presence of transient errors. If the underlying
// reader returns an error during the read operation, ReadHeader will return
// that error (potentially wrapped). If errors in the underlying reader are
// non-fatal, you can retry ReadHeader to resume the previous, erroneous call.
func (d *Decoder) ReadHeader() (Header, io.ReadCloser, error) {
	h, err := d.PeekHeader()
	if err != nil {
		return h, nil, err
	}
	// successful parse, consume the header

	if h.Tag == TagEndOfContents {
		d.state.pop(d.peekBytes)
	} else {
		d.state.push(h, d.peekBytes)
	}
	d.peekLen = 0
	d.peekBytes = 0

	// adjust buffering
	switch d.StackDepth() {
	case 1: // we have just read the start of a top-level data value
		d.buf.SetLimit(d.curr.Length)
	case 0: // we have just read the end of a top-level data value
		d.buf.SetLimit(0)
	}
	if d.curr.Constructed || h.Tag == TagEndOfContents {
		return h, nil, nil
	}
	d.val = valueReader{d, d.curr.Remaining()}
	return h, &d.val, nil
}

// PeekHeader reads the next TLV header from the input without advancing d. You
// can consume the peeked header using the ReadHeader method.
//
// PeekHeader shares the same semantics as ReadHeader. In particular at the end
// of constructed data values there is always an EndOfContents (even for
// definite-length data values) and transient errors from the underlying reader
// can be retried.
func (d *Decoder) PeekHeader() (Header, error) {
	if d.val.isValid() {
		if d.curr.Constructed {
			// we have begun discarding the current value. We cannot read a TLV here
			return Header{}, errors.New("tlv: invalid state")
		} else {
			return Header{}, errors.New("tlv: value not closed after reading")
		}
	}
	d.peekAt = 0
	h, err := d.readHeader()
	if err != nil {
		if _, ok := err.(*ioError); err == io.EOF || ok {
			return h, err
		}
		sErr := &SyntaxError{ByteOffset: d.offset, Header: d.curr.Header, Err: err}
		//goland:noinspection GoDirectComparisonOfErrors
		if err == io.ErrUnexpectedEOF {
			sErr.ByteOffset += int64(d.peekBytes)
		}
		return h, sErr
	}
	return h, nil
}

// readHeader decodes a TLV header from d. If decoding fails or an invalid TLV
// structure is detected, an error is returned.
func (d *Decoder) readHeader() (Header, error) {
	if d.curr.Header.Length != LengthIndefinite && d.curr.Remaining() == 0 {
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
		// The end-of-contents marker is 0x0000, coinciding with the empty header.
		return h, nil
	}
	if h == (Header{}) {
		err = errUnexpectedEOC
	} else if h.Tag == TagEndOfContents {
		// enc-of-contents is a reserved tag
		err = errInvalidEOC
	} else if !h.Constructed && h.Length == LengthIndefinite {
		err = errors.New("indefinite-length primitive data value")
	} else if h.Length != LengthIndefinite && uint(d.peekBytes+h.Length) > uint(d.curr.Remaining()) {
		// uint conversion takes care of indefinite length
		err = errors.New("data value exceeds parent")
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
		var n asn1.Tag
		n, err = vlq.ReadMinimal[asn1.Tag](byteReaderFunc(d.readByte))
		if err != nil {
			return h, noEOF(err)
		}

		h.Tag = h.Tag.Class() | (n &^ (0b11 << 14))
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
	if d.curr.Remaining() == d.peekBytes {
		return 0, errTruncated
	}

	if d.peekAt < d.peekLen {
		b = d.peekBuf[d.peekAt]
	} else if b, err = d.br.ReadByte(); err == nil {
		d.peekBuf[d.peekAt] = b
		d.peekLen++
		d.peekBytes++
	} else if err != io.EOF {
		return 0, &ioError{"read", err}
	} else {
		return 0, err
	}

	d.peekAt++
	return b, nil
}

// discard discards the remainder of the current data value without validating
// the TLV syntax and removes it from the stack of d.
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
		return errors.New("cannot discard root data value")
	}
	if d.curr.Length == LengthIndefinite {
		return errors.New("cannot discard indefinite number of bytes")
	}
	if !d.val.isValid() {
		// pretend the current TLV uses primitive encoding to discard it
		d.val = valueReader{d, d.curr.Remaining() - d.peekBytes}
	}

	// Close discards the rest of val and calls d.valueDone.
	return noEOF(d.val.Close())
}

// valueDone gets called by the valueReader type when a data value has been fully read.
// d automatically updates its state accordingly.
func (d *Decoder) valueDone() {
	if d.val.Len() != 0 {
		panic("BUG: value is not completely read")
	}
	d.val.d = nil

	// We have read or discarded the entire data value.
	// The next byte is the start of another TLV.
	//
	// d.peekBytes might be non-zero when discarding a constructed value
	d.state.pop(d.curr.Remaining() + d.peekBytes)
	d.peekBytes = 0
	d.peekLen = 0
}

// Skip discards the remainder of the current data value. If it uses the primitive
// encoding, only that value is discarded. If it is constructed, everything until
// the matching end-of-contents is skipped.
//
// If at any point an error is encountered, the skipping will be stopped and the
// error returned.
func (d *Decoder) Skip() (err error) {
	if !d.curr.Constructed {
		return d.discard()
	}
	depth := d.StackDepth()
	var val io.ReadCloser
	for d.StackDepth() >= depth && err == nil {
		_, val, err = d.ReadHeader()
		if err == nil && val != nil {
			err = val.Close()
		}
	}
	return err
}

// DataValueOffset returns the input byte offset where the current data value
// starts. This is the first byte of the identifier octets of the current value.
func (d *Decoder) DataValueOffset() int64 {
	return d.curr.Start
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
	if d.val.isValid() {
		// this never happens if d.curr.Length is indefinite
		// d.peekBytes can be non-zero when discarding a constructed element
		return d.offset + int64(d.curr.Length-d.val.Len()) + int64(d.peekBytes)
	}
	return d.offset
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
// data value with tag 0.
func (d *Decoder) StackIndex(i int) Header {
	if i == len(d.stack) {
		return d.curr.Header
	}
	return d.stack[i].Header
}

//endregion
