// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bufio"
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"codello.dev/asn1"
	"codello.dev/asn1/internal"
)

// BerDecoder is the interfaces implemented by types that can decode themselves
// from a binary representation in BER-encoding. In addition, types may want to
// implement the [BerMatcher] interface to provide support for optional types.
//
// The reader r reads the content octets of a data value encoding, identified by
// tag. In particular r does not read the tag and length bytes of the data value
// encoding. At the end of the content octets r returns io.EOF, even if there
// are more bytes in the original data stream. If an implementation does not
// read r to completion, any remaining bytes are discarded. If r.Constructed()
// returns true, the remaining data value encodings are syntactically validated.
//
// Implementations must attempt to decode from r irrespective of the tag.
// However, implementations may alter their decoding behavior according to the
// tag used. Implementations SHOULD validate that r.Constructed() meets the
// requirements of the data value encoding. If decoding fails, an error must be
// returned that explains the failure. Usually such an error should be a
// [SyntaxError] or [StructuralError]. Implementations can also return
// [io.ErrUnexpectedEOF] to indicate that r returned io.EOF before the entire
// data was read.
//
// The length of the data value encoding is available through r. Note that an
// indefinite-length encoding may be used in which case r might indicate a
// length of [LengthIndefinite].
type BerDecoder interface {
	BerDecode(tag asn1.Tag, r Reader) error
}

// BerMatcher can be implemented by types that implement [BerDecoder] to add
// support for optional types. The BerMatch method is consulted if no tag number
// is given via struct tags. Implementations implement this interface by
// returning a boolean value indicating whether h.Class and h.Tag match the
// intrinsic tag of the data value i.e., if based on the h.Class and h.Tag it is
// expected that decoding will succeed.
type BerMatcher interface {
	BerMatch(asn1.Tag) bool
}

//region error types

// InvalidDecodeError indicates that an invalid value was passed to an Unmarshal
// or Decode function. The invalid value might be nested within the passed
// value.
type InvalidDecodeError struct {
	Value reflect.Value
	msg   string // optional
}

func (e *InvalidDecodeError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	if !e.Value.IsValid() {
		return "cannot decode into nil value"
	}
	if e.Value.Kind() == reflect.Interface {
		if e.Value.IsNil() {
			return "cannot decode into nil interface of type " + e.Value.Type().String()
		}
		el := e.Value.Elem()
		if el.Kind() != reflect.Pointer {
			return "cannot decode into non-addressable interface value of type " + el.Type().String()
		}
		if el.IsNil() {
			return "cannot decode into non-addressable nil pointer of type " + el.Type().String()
		}
	} else if e.Value.Kind() == reflect.Pointer && e.Value.IsNil() {
		return "cannot decode into nil pointer of type " + e.Value.Type().String()
	} else if !e.Value.CanAddr() {
		return "cannot decode into non-pointer type " + e.Value.Type().String()
	}
	return "unsupported Go type: " + e.Value.Type().String()
}

// A SyntaxError suggests that the ASN.1 data is invalid. This can either
// indicate that the nesting of structured encodings contains an error, or that
// a primitive encoding could not be converted into a valid value.
//
// For errors that are not directly related to the syntax of the BER byte
// stream, [StructuralError] is a better fit.
type SyntaxError struct {
	Tag asn1.Tag // where the syntax error occurred
	Err error
}

func (e *SyntaxError) Error() string {
	var s strings.Builder
	s.WriteString("syntax error")
	if e.Tag != 0 {
		s.WriteString(" decoding ")
		s.WriteString(e.Tag.String())
	}
	if e.Err != nil {
		s.WriteString(": ")
		s.WriteString(e.Err.Error())
	}
	return s.String()
}

func (e *SyntaxError) Unwrap() error {
	return e.Err
}

// A StructuralError suggests that the ASN.1 data is valid, but the Go type
// which is receiving it doesn't match or can't fit the data.
//
// See also [SyntaxError].
type StructuralError struct {
	Tag  asn1.Tag
	Type reflect.Type
	Err  error
}

func (e *StructuralError) Error() string {
	var s strings.Builder
	s.WriteString("structural error")
	if e.Tag != 0 || e.Type != nil {
		s.WriteString(" decoding")
		if e.Tag != 0 {
			s.WriteByte(' ')
			s.WriteString(e.Tag.String())
		}
		if e.Type != nil {
			s.WriteString(" into ")
			s.WriteString(e.Type.String())
		}
	}
	if e.Err != nil {
		s.WriteString(": ")
		s.WriteString(e.Err.Error())
	}
	return s.String()
}

func (e *StructuralError) Unwrap() error {
	return e.Err
}

//endregion

//region types Reader and reader

// Reader is a reader type for reading data value encodings.
//
// Data value encodings can be primitive or constructed. Depending on the
// encoding only certain methods can be used. Reading methods of a Reader return
// io.EOF after the content octets of the encoding are read to completion,
// although the underlying data source might have more bytes available. Before
// the content octets is read to completion, io.ErrUnexpectedEOF may be returned.
//
// Closing a Reader is optional. Closing validates that the remaining bytes of a
// constructed encodings are valid BER-encoding.
type Reader interface {
	// Constructed reports whether this Reader is reading a constructed or
	// primitive encoding.
	Constructed() bool

	// Next parses the next component of a constructed encoding. If the Reader uses
	// the primitive encoding, an error is returned.
	//
	// The returned Reader is valid until the next call to Next(). If it is not read
	// to completion, any remaining bytes will be discarded when Next() is called
	// again. It is the responsibility of the caller to close the returned Reader in
	// order to validate the syntax of any remaining bytes.
	//
	// If no more data values are available, io.EOF is returned.
	Next() (Header, Reader, error) // only constructed

	// More reports whether the reader is in a valid state to decode more data. This
	// method does not indicate if reading the next data value or byte will succeed. In
	// particular a return value of true does not guarantee that Next() or Read()
	// does not return an error. After Next() or Read() has returned an io.EOF
	// error, this method will return false.
	//
	// For primitive encodings this is equivalent to Len() > 0.
	More() bool

	// Len returns the number of bytes remaining in the reader or -1 if its size is
	// unknown. Before Read(), ReadByte(), Close(), or Next() is called this returns
	// the indicated length of the encoding. If the constructed indefinite-length
	// encoding is used but a surrounding encoding uses a fixed length encoding,
	// this returns the number of remaining bytes in that parent.
	//
	// When used with the constructed encoding the result after calling Next() is
	// undefined until the Reader returned by it has been closed.
	Len() int

	// Close notifies the Reader that no more data will be read. This will discard
	// any remaining bytes in the reader. If a constructed format is used, this will
	// validate the BER structure of the remaining bytes. If the remaining bytes are
	// not a valid BER encoding, an error is returned.
	//
	// It is safe to call Close() multiple times, however the following calls may
	// return different errors or nil.
	Close() error

	io.Reader     // only primitive
	io.ByteReader // only primitive
}

// reader is the primary implementation of Reader in this package. A reader can
// operate in two modes (primitive or constructed) indicated by H. Switching
// between the two modes is not supported.
type reader struct {
	H Header
	R *limitReader // underlying reader

	// curr is the last reader returned by Next.
	curr *reader
	// err indicates an irrecoverable syntax or reader error. If err != nil we
	// cannot be sure the state of the parser matches the intended BER encoding so
	// we cannot continue.
	err error

	// root indicates that Next() may return io.EOF when the underlying reader returns
	// io.EOF at the start of a data value encoding.
	root bool
}

// Constructed reports whether r is operating on a constructed or primitive
// encoding.
func (r *reader) Constructed() bool {
	return r.H.Constructed
}

// More indicates whether there might be more data in d that can be decoded.
//
// If r encounters a syntactically invalid encoding, it tries to discard the
// affected bytes so that decoding can continue. However, some errors are
// irrecoverable so that r is in an unsafe state where continuing might result
// in an inconsistent state.
//
// This method indicates whether r is in a valid state and can continue reading
// more data. This method does not indicate if there are more values. In
// particular, a return value of true does not guarantee that r.Next() does not
// return an error.
//
// After r.Next() or r.Read() has returned an io.EOF error, this method will
// return false.
func (r *reader) More() bool {
	return r.err == nil && (r.Len() == LengthIndefinite || r.Len() > 0)
}

// Len returns the number of bytes remaining in the reader or -1 if the number
// of bytes is not known.
func (r *reader) Len() int {
	return r.R.Len()
}

// Next parses the next data value encoding from r. This method implements
// [Reader], see [Reader.Next] for details. If r is not constructed, an error
// will be returned.
//
// The returned [Reader] is valid until the next call of Next. The caller
// of this method is responsible for closing the returned [Reader] in
// order to validate the syntax of any unread bytes. Any unread bytes will be
// discarded without validation when Next is called again.
func (r *reader) Next() (h Header, er Reader, err error) {
	if !r.Constructed() {
		return Header{}, nil, &SyntaxError{r.H.Tag, errors.New("primitive encoding")}
	}
	// r.curr is only set if r.err == nil
	if r.curr != nil {
		// Discard r.curr to ensure all bytes are read. We ignore syntax errors here as
		// that is in the responsibility of the caller.
		r.err = r.curr.discard()
		r.curr = nil
	}
	if r.err != nil {
		return Header{}, nil, r.err
	}
	h, err = decodeHeader(r.R)
	if err != nil {
		if err == io.EOF && r.H.Length == LengthIndefinite && !r.root {
			err = io.ErrUnexpectedEOF
		}
		if err == io.ErrUnexpectedEOF {
			err = &SyntaxError{r.H.Tag, fmt.Errorf("decoding child: %w", err)}
		}
		// Any error decoding the header is fatal: we might have read a partial header.
		// We cannot know that the following bytes are the start of a new encoding.
		r.err = err
		return Header{}, nil, r.err
	} else if h == (Header{}) && r.H.Length == LengthIndefinite {
		r.err = io.EOF
		return Header{}, nil, r.err
	} else if !h.Constructed && h.Length == LengthIndefinite {
		r.err = &SyntaxError{r.H.Tag, fmt.Errorf("primitive encodoing %s has indefinite length", h.Tag.String())}
		return Header{}, nil, r.err
	}
	// If we reach this point, the header is syntactically valid. All the following
	// errors are non-fatal as we might be able to discard the encoding successfully.

	if h == (Header{}) {
		err = &SyntaxError{r.H.Tag, errors.New("unexpected end of contents")}
	} else if h.Tag == asn1.TagReserved && (h.Constructed || h.Length != 0) {
		err = &SyntaxError{r.H.Tag, errors.New("encountered invalid end of contents")}
	}
	lr := &limitReader{r.R, h.Length}
	if h.Length == LengthIndefinite {
		// This makes lr.Len() return a useful value. That way we can check if nested
		// encodings inside indefinite-length encodings exceed a surrounding
		// definite-length encoding.
		lr.N = r.R.Len()
	} else if r.R.Limited() && h.Length > r.R.Len() {
		// We return the reader for the encoding as the content octets may still be
		// useful. We do not adjust lr.Len() in order to trigger an ErrUnexpectedEOF
		// when reading the encoding.
		err = &SyntaxError{r.H.Tag, fmt.Errorf("encoding %s exceeds its parent", h.Tag.String())}
	}
	r.curr = &reader{H: h, R: lr}
	return h, r.curr, err
}

// Close closes r. If r is primitive any unread bytes are discarded. If r is
// using the constructed encoding this recursively validates that the content
// octets of r are syntactically valid. If a syntax error is encountered, it is
// returned and validation stops.
func (r *reader) Close() (err error) {
	if !r.Constructed() {
		return r.discard() // no syntax requirements
	}

	extended := false
	// calling Close() multiple times will return successively return all errors
	// encountered. If the BER encoding is structurally unambiguous repeated calls
	// to Close() will eventually return nil.
	for err = r.err; err == nil; {
		if r.curr == nil {
			_, _, err = r.Next()
			extended = r.curr != nil
		} else if err = r.curr.Close(); err == nil {
			r.curr = nil
		}
	}
	if err != io.EOF {
		return err
	}
	// FIXME: Maybe also check extensibilityImplied?
	if extended {
		return &SyntaxError{r.H.Tag, errors.New("extra data in non-extensible context")}
	}
	return nil
}

// discard discards any unread data in r. If r uses the definite-length format
// the unread bytes are simply discarded. If r uses the indefinite-length
// encoding r.Next is called (which recursively discards unprocessed data) until
// io.EOF is encountered.
//
// If it is not possible to discard all remaining bytes of r, an error is
// returned. This error is fatal and indicates that r cannot process any more
// data.
func (r *reader) discard() (err error) {
	if r.H.Length != LengthIndefinite {
		_, err = r.R.Discard(r.R.N)
		if r.err == nil {
			r.err = err
		}
	} else {
		for r.err == nil {
			_, _, err = r.Next() // calls discard() recursively
		}
		if r.err == io.EOF {
			err = nil
		}
	}
	return err
}

// Read implements the io.Reader interface. If r is using the constructed
// encoding, this method returns an error.
func (r *reader) Read(p []byte) (n int, err error) {
	if r.Constructed() {
		return 0, &SyntaxError{r.H.Tag, errors.New("constructed encoding")}
	}
	if r.err != nil {
		return 0, r.err
	}
	return r.R.Read(p)
}

// ReadByte implements the io.ByteReader interface. If r is using the
// constructed encoding, this method returns an error.
func (r *reader) ReadByte() (byte, error) {
	if r.Constructed() {
		return 0, &SyntaxError{r.H.Tag, errors.New("constructed encoding")}
	}
	if r.err != nil {
		return 0, r.err
	}
	return r.R.ReadByte()
}

//endregion

//region type limitReader

// limitReader works similar to [io.LimitedReader] but supports unlimited
// lengths and implements [io.ByteReader]. If an io.EOF is encountered before a
// definite limit is reached, io.ErrUnexpectedEOF is returned.
type limitReader struct {
	R io.Reader
	N int // -1 means unlimited
}

// Len returns the number of bytes remaining in r, or -1 if r is unlimited.
func (r *limitReader) Len() int {
	return r.N
}

// Limited indicates whether r is limited or unlimited.
func (r *limitReader) Limited() bool {
	return r.N != LengthIndefinite
}

// Read reads up to len(p) bytes from r, but at most r.Len() bytes if r is limited.
func (r *limitReader) Read(p []byte) (int, error) {
	if r.Len() == 0 {
		return 0, io.EOF
	}
	if !r.Limited() {
		return r.R.Read(p)
	}
	if len(p) > r.Len() {
		p = p[0:r.Len()]
	}
	n, err := r.R.Read(p)
	r.N -= n
	if r.N > 0 && err == io.EOF {
		// if the underlying reader returns io.EOF with data and r.N == 0
		// we can pass through the EOF.
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// ReadByte reads a single byte from r. If the underlying reader of r does not
// implement io.ByteReader this method reads a single byte using its Read
// method. Note that this can be inefficient and should be avoided.
func (r *limitReader) ReadByte() (b byte, err error) {
	if r.Len() == 0 {
		return 0, io.EOF
	}
	if br, ok := r.R.(io.ByteReader); ok {
		b, err = br.ReadByte()
	} else {
		var bs [1]byte
		_, err = io.ReadFull(r.R, bs[:])
		b = bs[0]
	}
	if !r.Limited() {
		return b, err
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, err
	}
	r.N--
	return b, nil
}

// Discard discards up to n bytes from r. It returns the number of bytes
// discarded. An error is returned iff discarded < n.
//
// If the underlying reader of r implements either its own Discard method or the
// io.Seeker interface, these methods will be used for more efficient
// discarding.
func (r *limitReader) Discard(n int) (discarded int, err error) {
	if n == 0 {
		return
	}
	discard := n
	if r.Limited() && r.Len() < discard {
		discard = r.Len()
	}
	switch rd := r.R.(type) {
	case interface{ Discard(int) (int, error) }: // implemented by *bufio.Reader
		discarded, err = rd.Discard(discard)
	case io.Seeker: // implemented by bytes.Reader
		var d int64
		d, err = rd.Seek(int64(discard), io.SeekCurrent)
		discarded = int(d)
	default:
		var d int64
		d, err = io.CopyN(io.Discard, rd, int64(discard))
		discarded = int(d)
	}
	if r.Len() == LengthIndefinite {
		return discard, err
	}
	if n > r.Len() && err == nil {
		err = io.EOF
	} else if n < r.Len() && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	r.N -= discarded
	return discarded, err
}

//endregion

//region type bufferedReader

// bufferedReader wraps a [*bufio.Reader] together with another io.Reader in a
// similar fashion to an [io.MultiReader]. In contrast to the multi reader
// bufferedReader does not read buf to completion but only reads from its
// buffered portion before redirecting reads to r.
//
// The buffer is checked on each Read call.
type bufferedReader struct {
	buf *bufio.Reader
	r   io.Reader
}

func (r *bufferedReader) Read(p []byte) (n int, err error) {
	if r.buf.Buffered() > 0 {
		return r.buf.Read(p[:min(r.buf.Buffered(), len(p))])
	}
	return r.r.Read(p)
}

//endregion

//region type decoderReader

// decoderReader wraps a [Decoder] to implement the [Reader] interface.
// Methods of the interface not implemented by *Decoder panic.
type decoderReader struct {
	*Decoder
}

// Len returns -1 as d is of unknown length.
func (d *decoderReader) Len() int {
	return LengthIndefinite
}

// Constructed returns always true, as a [Decoder] is always constructed.
func (d *decoderReader) Constructed() bool {
	return true
}

func (d *decoderReader) Read(_ []byte) (n int, err error) {
	panic("internal error: primitive read from Decoder")
}

func (d *decoderReader) ReadByte() (byte, error) {
	panic("internal error: primitive read from Decoder")
}

func (d *decoderReader) Close() error {
	panic("internal error: closing a Decoder")
}

//endregion

//region type explicitDecoder

// explicitDecoder implements decoding of ASN.1 EXPLICIT types. Explicit types
// are wrapped in another constructed encoding with a unique tag. The tag is
// defined by struct tags so explicitDecoder does not have an intrinsic tag and
// does not implement [BerMatcher].
type explicitDecoder codec[BerDecoder]

// BerDecode decodes a single data value from r into d.dec.
func (d *explicitDecoder) BerDecode(tag asn1.Tag, r Reader) (err error) {
	if r.Len() == 0 {
		if _, ok := d.val.(flagCodec); !ok {
			return &StructuralError{tag, d.ref.Type(), errors.New("zero length explicit tag was not a asn1.Flag")}
		}
	} else if !r.Constructed() {
		return &SyntaxError{tag, errors.New("non-constructed encoding for explicit type")}
	}
	h, er, err := r.Next()
	if err != nil {
		return err
	}
	if err = d.val.BerDecode(h.Tag, er); err != nil {
		return err
	}
	if err = er.Close(); err != nil {
		return err
	}
	_, _, err = r.Next()
	if err == nil {
		return &SyntaxError{tag, errors.New("explicit type has multiple components")}
	}
	if err != io.EOF {
		return err
	}
	return nil
}

//endregion

//region type sequenceDecoder

// sequenceDecoder is a [BerDecoder] that decodes its contents into a slice or
// array. Decoding will overwrite any previous contents in the slice or array.
// Decoding into an array stops when the array is completely filled. If an array
// cannot be filled completely or there are additional values, an error is
// generated.
type sequenceDecoder codec[any] // slice or array type

// BerMatch returns true if h indicates a SEQUENCE or SET. If the underlying
// slice or array type implements [BerDecoder] the method is delegated.
func (d sequenceDecoder) BerMatch(tag asn1.Tag) bool {
	if bm, ok := d.val.(BerMatcher); ok {
		return bm.BerMatch(tag)
	}
	return tag == asn1.TagSequence || tag == asn1.TagSet
}

// BerDecode parses a sequence of data value encodings into d.Value. If d.Value
// is a slice it is resized according to the number of data value encodings
// found.
func (d sequenceDecoder) BerDecode(tag asn1.Tag, r Reader) (err error) {
	seqType := d.ref.Type()
	elemType := seqType.Elem()
	slice := d.ref
	if seqType.Kind() == reflect.Slice {
		if d.ref.IsNil() {
			slice = reflect.MakeSlice(seqType, 0, 10)
		} else {
			slice = slice.Slice(0, 0)
		}
	}

	var (
		i      int
		params internal.FieldParameters
		h      Header
		er     Reader
	)
	for i = 0; err == nil && (d.ref.Kind() != reflect.Array || i < d.ref.Len()); i++ {
		if h, er, err = r.Next(); err != nil {
			break
		}
		// allocate a new addressable zero value
		vp := reflect.New(elemType)
		if err = decodeValue(h.Tag, er, vp.Elem(), params); err != nil {
			break
		}
		err = er.Close()
		if seqType.Kind() == reflect.Slice {
			slice = reflect.Append(slice, vp.Elem())
		} else {
			slice.Index(i).Set(vp.Elem())
		}
	}
	d.ref.Set(slice)

	for ; err == nil; i++ {
		// read all extra values until we hit an error
		if _, er, err = r.Next(); err == nil {
			err = er.Close()
		}
	}
	if err != io.EOF {
		return err
	}
	i-- // the last EOF does not correspond to another value
	if i > d.ref.Len() {
		return &StructuralError{tag, d.ref.Type(), errors.New("too many values")}
	}
	if d.ref.Kind() == reflect.Array && i < d.ref.Len() {
		return &StructuralError{tag, d.ref.Type(), errors.New("not enough values")}
	}
	return nil
}

//endregion

//region type structDecoder

// structDecoder is a [BerDecoder] that decodes its contents into the fields of
// a struct. Anonymous struct fields are processed recursively.
type structDecoder codec[any] // struct type

// BerMatch indicates the intrinsic type of d as an ASN.1 SEQUENCE. If the
// underlying type implements [BerMatcher] the method call is delegated.
func (d structDecoder) BerMatch(tag asn1.Tag) bool {
	if bm, ok := d.val.(BerMatcher); ok {
		return bm.BerMatch(tag)
	}
	return tag == asn1.TagSequence
}

// BerDecode decodes the BER-encoded data from r into the underlying struct of
// d. Anonymous fields without struct tags are processed recursively.
func (d structDecoder) BerDecode(tag asn1.Tag, r Reader) error {
	h, er, err := r.Next()
	for field, params := range internal.StructFields(d.ref) {
		if err != nil {
			if err != io.EOF {
				return err
			}
			if !params.Optional {
				return &StructuralError{tag, d.ref.Type(), errors.New("not enough values")}
			}
			continue
		}
		if field.Type() == internal.ExtensibleType {
			// read and validate all remaining data value encodings
			err = er.Close()
			for err == nil {
				if _, er, err = r.Next(); err == nil {
					err = er.Close()
				}
			}
			continue
		}
		if err = decodeValue(h.Tag, er, field, params); err == nil {
			if err = er.Close(); err == nil {
				h, er, err = r.Next()
				continue
			}
			return err
		}
		if errors.Is(err, errTagMismatch) && params.Optional {
			err = nil
			continue
		}
		return err
	}

	hasExtra := false
	if err == nil {
		hasExtra = true
		err = er.Close()
	}
	for err == nil {
		// read and validate all remaining data value encodings
		if _, er, err = r.Next(); err == nil {
			err = er.Close()
		}
	}
	if err != io.EOF {
		return err
	}
	if hasExtra {
		return &StructuralError{tag, d.ref.Type(), errors.New("too many values")}
	}
	return nil
}

//endregion

//region decoderConfig and decoder selection

// errTagMismatch is a sentinel error returned by decodeValue that indicates that
// the field type did not match the provided header. This error is used to
// implement optional types.
var errTagMismatch = errors.New("tag does not match")

// decodeValue is the main decoding function. It finds a BerDecoder for v using
// the makeDecoder function and then invokes its BerDecode method. Any error
// that occurs is returned. If the BerDecoder returns io.ErrUnexpectedEOF after
// reading all its bytes, the error is replaced by a SyntaxError.
//
// If it is determined that v does not match the header h, an error wrapping
// errTagMismatch is returned. If no decoder is available for v, decodeValue
// returns an InvalidDecodeError.
func decodeValue(tag asn1.Tag, r Reader, v reflect.Value, params internal.FieldParameters) error {
	dec, err := makeDecoder(tag, v, params)
	if err != nil {
		return err
	}
	err = dec.BerDecode(tag, r)
	if errors.Is(err, io.ErrUnexpectedEOF) && r.Len() == 0 {
		err = &SyntaxError{tag, errors.New("not enough bytes")}
	} else if err == io.EOF {
		// Semantically io.EOF does not really make sense. We assume that
		// dec.BerDecode() returned an error from the underlying reader without properly
		// inspecting it. As io.EOF indicates that the reader finished successfully we
		// treat this as a success value.
		err = nil
	}
	return err
}

// makeDecoder walks down v allocating pointers as needed, until it gets to a
// non-pointer. If it encounters a type that implements [BerDecoder] or
// [encoding.BinaryUnmarshaler], makeDecoder stops and returns that. If params
// indicate an explicit tag that differs from h or if the decoder for type v
// implements [BerMatcher] and does not match h, an error wrapping
// errTagMismatch is returned. If no decoder is available for v, makeDecoder
// returns an InvalidDecodeError.
func makeDecoder(tag asn1.Tag, v reflect.Value, params internal.FieldParameters) (ret BerDecoder, err error) {
	if params.Nullable && tag == asn1.TagNull {
		return nullCodec{ref: v}, nil
	}

	// we have an explicitly set tag. ignore the intrinsic type match
	if params.Tag != 0 && tag != params.Tag {
		return nil, &StructuralError{tag, v.Type(), fmt.Errorf("explicit encoding %s: %w", params.Tag.String(), errTagMismatch)}
	}

	// if we encounter a (potentially nested) nil pointer we store it in field and
	// continue to operate on a newValue. If we find a match we set field to the
	// newValue.
	var field, fieldValue reflect.Value

	defer func() {
		if ret == nil {
			return
		}
		// params.tag != nil means that explicit tags are present that have been checked
		// at the beginning of makeDecoder().
		if params.Tag == 0 && v.Kind() != reflect.Interface {
			if m, ok := ret.(BerMatcher); ok && !m.BerMatch(tag) {
				ret = nil
				err = &StructuralError{tag, v.Type(), errTagMismatch}
				return
			}
		}
		if params.Explicit {
			ret = &explicitDecoder{v, ret}
		}
		if field.IsValid() {
			field.Set(fieldValue)
		}
	}()

	// Issue #24153 indicates that it is generally not a guaranteed property
	// that you may round-trip a reflect.Value by calling Value.Addr().Elem()
	// and expect the value to still be settable for values derived from
	// unexported embedded struct fields.
	//
	// The logic below effectively does this when it first addresses the value
	// (to satisfy possible pointer methods) and continues to dereference
	// subsequent pointers as necessary.
	//
	// After the first round-trip, we set v back to the original value to
	// preserve the original RW flags contained in reflect.Value.
	v0 := v
	haveAddr := false

	// If v is a named type and is addressable, start with its address, so that if
	// the type has pointer methods, we find them.
	if v.Kind() != reflect.Pointer && v.Type().Name() != "" && v.CanAddr() {
		v = v.Addr()
		haveAddr = true
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.Kind() == reflect.Interface {
			if v.IsNil() {
				if v.NumMethod() == 0 {
					// v has type interface{}
					return codecFor(v, nil, tag), nil
				}
			} else if e := v.Elem(); e.Kind() == reflect.Pointer && !e.IsNil() {
				// Load value from interface, but only if the result will be usefully
				// addressable.
				haveAddr = false
				v = e
				continue
			}
			return nil, &InvalidDecodeError{Value: v}
		}

		// Prevent infinite loop if v is an interface pointing to its own address:
		//     var v interface{}
		//     v = &v
		// In this case we pretend the value was set to nil and continue.
		if v.Elem().Kind() == reflect.Interface && v.Elem().Elem() == v {
			v = v.Elem()
			return codecFor(v, nil, tag), nil
		}
		if v.IsNil() {
			// Allocate a value for the pointer so that we can invoke methods. We do not set
			// the value immediately because we don't know yet if the value matches the type.
			if field.IsValid() {
				v.Set(reflect.New(v.Type().Elem()))
			} else {
				field = v
				fieldValue = reflect.New(v.Type().Elem())
				v = fieldValue
			}
		}
		switch vv := v.Interface().(type) {
		case BerDecoder:
			return vv, nil
		case encoding.BinaryUnmarshaler:
			return binaryUnmarshalerCodec{v, vv}, nil
		}

		if haveAddr {
			v = v0 // restore original value after round-trip Value.Addr().Elem()
			haveAddr = false
		} else {
			v = v.Elem()
		}
	}

	vif := v.Interface()
	// handle value types that implement these interfaces and known Go types
	switch vv := vif.(type) {
	case BerDecoder:
		return vv, nil
	case encoding.BinaryUnmarshaler:
		return binaryUnmarshalerCodec{v, vv}, nil
	}
	dec := codecFor(v, vif, params.Tag)
	if dec != nil {
		return dec, nil
	}

	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return sequenceDecoder{v, vif}, nil
	case reflect.Struct:
		return structDecoder{v, vif}, nil
	default:
		return nil, &InvalidDecodeError{Value: v}
	}
}

//endregion

//region type Decoder

// Decoder implements stream-based decoding of BER-encoded ASN.1 types. The
// Decoder type implements specialized buffering for BER-data. See the
// [NewDecoder] function for details.
//
// To create a Decoder, use the [NewDecoder] function.
type Decoder struct {
	r Reader

	// buf is a reusable, buffered reader of lr
	// that is used if r is not an io.ByteReader.
	// buf is limited by lr.
	buf *bufio.Reader
	// lr limits buf so that it does not exceed
	// the current data value encoding.
	lr *limitReader
}

// NewDecoder creates a new [Decoder] reading from r.
//
// Decoding BER requires single-byte reads. If r implements [io.ByteReader] then
// it is assumed that the reader is efficient enough so no buffering is done by
// d. Assuming that r produces a valid BER-encoding then d will never read more
// bytes than required to parse one data value.
//
// If r implements [Reader] and is reading a constructed encoding, d will
// decode directly from r without additional buffering.
//
// If r does not implement [io.ByteReader] then the [Decoder] will use its own
// buffering. If possible buffering is restricted to a single BER-encoded type:
// As long as the BER-encoded types read from r only use a definite-length
// format on the top-level encoding, d will not read more bytes from r than
// required to parse one value. If the indefinite-length encoding is used, then
// d might read more bytes from r than needed.
func NewDecoder(r io.Reader) (d *Decoder) {
	if er, ok := r.(Reader); ok && er.Constructed() {
		return &Decoder{r: er}
	}
	er := &reader{
		H:    Header{Constructed: true, Length: LengthIndefinite},
		R:    &limitReader{r, LengthIndefinite},
		root: true,
	}
	d = &Decoder{r: er}
	// if the underlying reader is an io.ByteReader we assume that it is efficient
	// enough so we don't need to add buffering
	if _, ok := r.(io.ByteReader); !ok {
		d.lr = &limitReader{r, LengthIndefinite}
		d.buf = bufio.NewReaderSize(d.lr, 512)
		er.R.R = &bufferedReader{d.buf, r}
	}
	return d
}

// More indicates whether there might be more data values in d that can be decoded.
//
// If d encounters a syntactically invalid data value encoding, d tries to
// discard the respective encoding so that decoding can continue. However, some
// errors are irrecoverable so that d is in an unsafe state where decoding is no
// longer valid.
//
// This method indicates whether d is in a valid state and can decode more
// values. This method does not indicate if there are actually more data value
// encodings to be decoded. In particular a return value of true does not
// guarantee that d.Next() does not return an error.
//
// After d.Next() has returned an io.EOF error, this method will return false.
func (d *Decoder) More() bool {
	return d.r.More()
}

// Next parses the next data value encoding from d.
//
// The returned Reader is valid until the next call to Next(). If the
// reader is not read to completion, any remaining bytes will be discarded when
// Next() is called. It is the responsibility of the caller to close the
// returned Reader in order to validate the syntax of any remaining
// bytes.
//
// If no more values are available, io.EOF is returned.
func (d *Decoder) Next() (Header, Reader, error) {
	h, er, err := d.r.Next()
	if er != nil && d.buf != nil {
		//goland:noinspection GoDfaErrorMayBeNotNil
		if h.Length == LengthIndefinite {
			d.lr.N = LengthIndefinite
		} else {
			// We have some buffering left over from a previous call to Next().
			// Adjust the limit for future buffer fills.
			//
			// Note that if d.buf has read io.EOF from d.lr then we have the two cases:
			//  - The encoding was discarded during d.r.Next(). Then d.buf.Buffered() is 0
			//    and we reset the buffer below.
			//  - The encoding was not discarded due to an error. Then d.r.Next() will not
			//    return a Reader so we won't get here.
			d.lr.N = h.Length - d.buf.Buffered()
		}
		if d.buf.Buffered() == 0 {
			// d.buf might have read to EOF of the d.lr so we need to reset
			d.buf.Reset(d.lr)
		}
		er.(*reader).R.R = d.buf
	}
	return h, er, err
}

// Decode parses a BER-encoded ASN.1 data structure and uses the reflect package
// to fill in an arbitrary value pointed at by val. Because Decode uses the
// reflect package, the structs being written to must use exported (upper case)
// field names. If val is nil or not a pointer, Unmarshal returns an error.
func (d *Decoder) Decode(val any) error {
	return d.DecodeWithParams(val, "")
}

// DecodeWithParams works like [Decoder.Decode] but accepts additional
// parameters applied to the top-level data value encoding. The format for
// params is the same as for struct tags supported by this package. Using the
// `asn1:"optional"` or `asn1:"-"` options has no effect here.
func (d *Decoder) DecodeWithParams(val any, params string) error {
	fp := internal.ParseFieldParameters(params)
	v := reflect.ValueOf(val)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return &InvalidDecodeError{Value: v}
	}

	h, er, err := d.Next()
	if err != nil {
		return err
	}
	if err = decodeValue(h.Tag, er, v.Elem(), fp); err == nil {
		err = er.Close()
	}
	return err
}

// DecodeAll decodes all values from d into the value pointed to by val. The
// value pointed to by val must be able to decode a constructed ASN.1 type. See
// [Decoder.Decode] for details on the decoding process.
//
// This method blocks until the underlying reader of d returns io.EOF, or an
// error is encountered.
func (d *Decoder) DecodeAll(val any) error {
	v := reflect.ValueOf(val)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return &InvalidDecodeError{Value: v}
	}
	return decodeValue(asn1.TagSequence, &decoderReader{d}, v.Elem(), internal.FieldParameters{})
}

//endregion

// Unmarshal parses a BER-encoded ASN.1 data structure from b. See
// [Decoder.Decode] for details. If any data is left over in b after val has
// been decoded, an error is returned.
func Unmarshal(b []byte, val any) error {
	return UnmarshalWithParams(b, val, "")
}

// UnmarshalWithParams allows field parameters to be specified for the top-level
// data value encoding. The form of the params is the same as the field tags.
// See [Decoder.Decode] for details.
func UnmarshalWithParams(b []byte, val any, params string) error {
	r := bytes.NewReader(b)
	d := NewDecoder(r)
	err := d.DecodeWithParams(val, params)
	if err == nil && r.Len() > 0 {
		return errors.New("extra data after data value encoding")
	}
	return err
}
