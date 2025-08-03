// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bufio"
	"bytes"
	"encoding"
	"errors"
	"io"
	"reflect"
	"strings"

	"codello.dev/asn1"
	"codello.dev/asn1/internal"
)

// BerEncoder is an interface that can be implemented by types that provide
// custom logic to encode themselves as an ASN.1 type using Basic Encoding
// Rules.
//
// Encoding using BER is a two-step process: First the size of data values is
// estimated and then data value encoding bytes are written to a byte stream.
// The BerEncode method realizes this by returning an io.WriterTo instead of
// writing data directly to a writer. Implementations write exactly the amount
// of bytes promised by h.Length. The writer passed to wt implements
// [io.ByteWriter].
//
// Implementations should return any validation errors from BerEncode. Errors
// returned from wt are assumed to be writing errors of the underlying writer.
//
// If a data value encoding uses the indefinite-length format, the final two
// zero octets are written automatically and must not be written by wt. Custom
// constructed encodings may want to use the [Sequence] type. Note that struct
// tags override the class and tag of the returned header.
type BerEncoder interface {
	BerEncode() (h Header, wt io.WriterTo, err error)
}

// writerFunc wraps a function and implements the [io.WriterTo] interface. This
// type can be useful when implementing a custom [BerEncoder].
type writerFunc func(io.Writer) (int64, error)

func (fn writerFunc) WriteTo(w io.Writer) (int64, error) {
	return fn(w)
}

//region error types

// UnsupportedTypeError indicates that a value was passed to Marshal or an
// Encode function that cannot be encoded to BER.
type UnsupportedTypeError struct {
	Type reflect.Type
	msg  string
}

func (e *UnsupportedTypeError) Error() string {
	if e.msg == "" {
		return e.msg
	}
	if e.Type == nil {
		return "cannot encode or marshal nil value"
	}
	if e.Type.Kind() == reflect.Pointer {
		return "cannot encode nil pointer of type: " + e.Type.String()
	} else if e.Type.Kind() == reflect.Interface {
		return "cannot encode nil interface of type: " + e.Type.String()
	}
	return "cannot encode value of type " + e.Type.String() + ": unsupported Go type"
}

// EncodeError indicates that a value failed validation during encoding. Errors
// returned from a [BerDecoder] are wrapped in an EncodeError before they are
// returned from the [Encoder].
type EncodeError struct {
	Value reflect.Value
	Err   error
}

func (e *EncodeError) Error() string {
	var s strings.Builder
	s.WriteString("encode error")
	if e.Value.IsValid() {
		s.WriteString(" for ")
		s.WriteString(e.Value.Type().String())
	}
	s.WriteString(": ")
	s.WriteString(e.Err.Error())
	return s.String()
}

func (e *EncodeError) Unwrap() error {
	return e.Err
}

//endregion

//region type Sequence

// Sequence is a type that simplifies the generation of constructed encodings.
// The zero value constitutes an empty sequence. If you want to implement a
// custom, constructed [BerEncoder] you can use a Sequence like this:
//
//	func (*myType) BerEncode() (asn1.Header, io.WriterTo, error) {
//		s := &Sequence{
//			Tag: asn1.ClassApplication | 15
//		}
//		s.Append("A String")
//		s.Append(42)
//		return s.BerEncode()
//	}
//
// Despite its name the Sequence type can be used to encode any constructed
// type, not just ASN.1 SEQUENCE types.
type Sequence struct {
	Tag asn1.Tag // defaults to [UNIVERSAL 16]

	values   []reflect.Value
	encoders []BerEncoder
	params   []internal.FieldParameters
}

// SequenceOf returns a sequence containing the data values representing the
// fields of the passed struct, slice, or array. If val is not a struct, slice,
// or array, or any if the values contained within val cannot be encoded, an
// error is returned.
func SequenceOf(val any) (s *Sequence, err error) {
	if val == nil {
		return nil, &UnsupportedTypeError{Type: nil}
	}
	v := reflect.ValueOf(val)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	s = &Sequence{}
	switch v.Kind() {
	case reflect.Struct:
		e := &Sequence{}
		for field, params := range internal.StructFields(v) {
			if err = e.append(field, params); err != nil {
				return s, err
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil, &UnsupportedTypeError{v.Type(), "cannot convert byte array or byte slice to sequence"}
		}
		e := &Sequence{}
		for i := range v.Len() {
			if err = e.append(v.Index(i), internal.FieldParameters{}); err != nil {
				return s, err
			}
		}
		return e, nil
	default:
		return nil, &UnsupportedTypeError{Type: v.Type(), msg: "value must be a struct or a slice"}
	}
	return s, nil
}

// Append adds a data value to the end of the sequence. If the type of val does
// not permit encoding to BER an error of type [UnsupportedTypeError] is
// returned. In particular if the type of val is supported, no error will be
// returned. Validation is deferred to the BerEncode method.
func (s *Sequence) Append(val ...any) error {
	for _, v := range val {
		err := s.append(reflect.ValueOf(v), internal.FieldParameters{})
		if err != nil {
			return err
		}
	}
	return nil
}

// AppendWithParams adds a data value to the end of the sequence. The format of
// params is the same as for struct tags documented in the documentation of this
// package. If the type of val does not permit encoding to BER an error of type
// [UnsupportedTypeError] is returned. In particular if the type of val is
// supported, no error will be returned. Validation is deferred to the BerEncode
// method.
func (s *Sequence) AppendWithParams(val any, params string) error {
	return s.append(reflect.ValueOf(val), internal.ParseFieldParameters(params))
}

// append adds a data value to the end of the sequence. The value is converted
// into a [BerDecoder]. If the conversion fails, an [UnsupportedTypeError] is
// returned. In particular if the type of v is supported, no error will be
// returned. Validation is deferred to the BerEncode method.
func (s *Sequence) append(v reflect.Value, params internal.FieldParameters) error {
	enc, err := makeEncoder(v, params)
	if err != nil {
		return err
	}
	if enc != nil {
		s.values = append(s.values, v)
		s.encoders = append(s.encoders, enc)
		s.params = append(s.params, params)
	}
	return nil
}

// BerEncode encodes the sequence into the BER format. The length of the
// returned header is calculated as follows:
//
//   - If any of the sequence values use the indefinite length format, the
//     resulting length is also indefinite.
//   - If the sum of the lengths of the encodings of s overflows the int type, the
//     resulting length is indefinite.
//   - Otherwise the length is the sum of the lengths of the encodings of s.
//
// If encoding of any data value fails, the error is returned by this method.
func (s *Sequence) BerEncode() (Header, io.WriterTo, error) {
	h := Header{s.Tag, 0, true}
	if h.Tag == 0 {
		h.Tag = asn1.TagSequence
	}

	headers := make([]Header, len(s.encoders))
	writers := make([]io.WriterTo, len(s.encoders))
	for i, enc := range s.encoders {
		eh, wt, err := encodeValue(s.values[i], enc, s.params[i])
		if err != nil {
			return Header{}, nil, err
		}
		headers[i] = eh
		writers[i] = wt
		h.Length = CombinedLength(h.Length, eh.numBytes(), eh.Length)
	}
	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		var n2 int64
		for i := 0; i < len(headers) && err == nil; i++ {
			n2, err = writeValue(s.values[i], w, headers[i], writers[i])
			n += n2
		}
		return n, err
	}), nil
}

//endregion

//region type explicitEncoder

// explicitEncoder wraps a [BerEncoder] in another constructed encoding. The tag
// is set via explicit struct tags thus an explicitEncoder has no intrinsic tag.
type explicitEncoder codec[BerEncoder]

// BerEncode wraps the underlying encoder of e in a new, constructed encoding.
// The tag will be set by an explicit struct tag.
func (e explicitEncoder) BerEncode() (Header, io.WriterTo, error) {
	h, wt, err := encodeValue(e.ref, e.val, internal.FieldParameters{})
	if err != nil {
		return Header{}, nil, err
	}
	ret := Header{Length: CombinedLength(h.numBytes(), h.Length), Constructed: true} // class and tag are set explicitly
	return ret, writerFunc(func(w io.Writer) (int64, error) {
		return writeValue(e.ref, w, h, wt)
	}), nil
}

//endregion

//region main encoding functions

// makeEncoder creates a [BerEncoder] that encodes v. If v is to be omitted, ret
// and err will both be nil. If no [BerEncoder] can be created for v, an
// [UnsupportedTypeError] will be returned.
func makeEncoder(v reflect.Value, params internal.FieldParameters) (ret BerEncoder, err error) {
	if !v.IsValid() {
		return nil, &UnsupportedTypeError{Type: nil}
	}

	if params.Explicit {
		defer func() {
			if ret != nil {
				ret = &explicitEncoder{v, ret}
			}
		}()
		params.Explicit = false
	}

	// If v is a named type and is addressable, start with its address, so that if
	// the type has pointer methods, we find them.
	if v.Kind() == reflect.Pointer && v.Type().Name() != "" && v.CanAddr() {
		v = v.Addr()
	}
	for (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) && !v.IsNil() {
		switch vv := v.Interface().(type) {
		case BerEncoder:
			return vv, nil
		case encoding.BinaryMarshaler:
			return binaryMarshalerCodec{v, vv}, nil
		}

		// Prevent infinite loop if v is an interface pointing to its own address:
		//     var v interface{}
		//     v = &v
		// In this case we pretend the value was set to nil and continue.
		if v.Kind() == reflect.Pointer && v.Elem().Kind() == reflect.Interface && v.Elem().Elem() == v {
			v = v.Elem()
			return nil, &UnsupportedTypeError{Type: v.Type(), msg: "cannot encode self-referential value"}
		}
		v = v.Elem()
	}

	vif := v.Interface()
	if z, ok := vif.(interface{ IsZero() bool }); (ok && z.IsZero()) || (!ok && v.IsZero()) {
		if params.OmitZero {
			return nil, nil
		} else if params.Nullable {
			return nullCodec{ref: v}, nil
		}
	}
	if v.Kind() == reflect.Interface || (v.Kind() == reflect.Pointer && v.IsNil()) {
		return nil, &UnsupportedTypeError{Type: nil}
	}

	switch vv := vif.(type) {
	case BerEncoder:
		return vv, nil
	case encoding.BinaryMarshaler:
		return binaryMarshalerCodec{v, vv}, nil
	}
	if vv, ok := vif.(BerEncoder); ok {
		return vv, nil
	}
	enc := codecFor(v, vif, params.Tag)
	if enc != nil {
		return enc, nil
	}
	switch v.Kind() {
	case reflect.Struct:
		e := &Sequence{}
		for field, params := range internal.StructFields(v) {
			if err = e.append(field, params); err != nil {
				return nil, err
			}
		}
		return e, nil
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return bytesCodec{ref: v}, nil
		}
		e := &Sequence{}
		for i := range v.Len() {
			if err = e.append(v.Index(i), internal.FieldParameters{}); err != nil {
				return nil, err
			}
		}
		return e, nil
	default:
		return nil, &UnsupportedTypeError{Type: v.Type()}
	}
}

// encodeValue begins encoding enc. This is the first step of the 2-step
// encoding process. The second step is implemented by writeValue.
//
// The header generated by enc may be replaced by a tag specified by params. If
// encoding fails, an [EncodeError] will be returned.
//
// The v argument is only used for error reporting.
func encodeValue(v reflect.Value, enc BerEncoder, params internal.FieldParameters) (Header, io.WriterTo, error) {
	h, wt, err := enc.BerEncode()
	if err != nil {
		if errors.As(err, new(*EncodeError)) {
			return h, wt, err
		}
		return h, wt, &EncodeError{v, err}
	}
	if h.Length == LengthIndefinite && !h.Constructed {
		return h, nil, &EncodeError{v, errors.New("primitive, indefinite length encoding")}
	}
	if params.Tag != 0 {
		h.Tag = params.Tag
	}
	if h.Tag == 0 {
		return h, wt, &EncodeError{v, errors.New("missing class or tag")}
	}
	return h, wt, nil
}

// writeValue writes the encoding of h and the content octets identified by wt
// to w. This is the second step of the 2-step encoding process. The first step
// is implemented by encodeValue.
//
// Any error generated by writing wt to w is returned as-is. If wt does not
// behave as defined by the [BerEncoder] interface, an [EncodeError] is
// returned. If wt fails to report the correct number of bytes written, the
// error will wrap io.ErrShortWrite.
//
// The v argument is only used for error reporting.
func writeValue(v reflect.Value, w io.Writer, h Header, wt io.WriterTo) (n int64, err error) {
	if h.Length == LengthIndefinite && !h.Constructed {
		panic("primitive, indefinite length encoding")
	}
	n, err = h.writeTo(w.(io.ByteWriter))
	if err != nil {
		return n, err
	}
	ew := &limitWriter{w, h.Length, 0}
	if wt != nil {
		n2, err := wt.WriteTo(ew)
		n += n2
		if err != nil {
			return n, err
		}
		if n2 != ew.C {
			return n - n2 + ew.C, &EncodeError{v, io.ErrShortWrite}
		}
	}
	if h.Length == LengthIndefinite {
		var n2 int
		n2, err = w.Write([]byte{0x00, 0x00})
		n += int64(n2)
	} else if ew.Len() != 0 {
		err = &EncodeError{v, errors.New("BerEncode did not write all its bytes")}
	}
	return n, err
}

// limitWriter wraps an [io.Writer] and adds two control mechanisms:
//
//   - limitWriter can limit the number of bytes written to the underlying
//     writer.
//   - limitWriter counts the number of bytes written by the underlying
//     writer.
//
// Setting N to [LengthIndefinite] disables the write limiter.
type limitWriter struct {
	W io.Writer
	N int   // remaining bytes
	C int64 // bytes written
}

// Len returns the number of bytes remaining in w. Writing more than Len() bytes
// will result in an error.
func (w *limitWriter) Len() int {
	return w.N
}

func (w *limitWriter) Write(p []byte) (n int, err error) {
	if w.N != LengthIndefinite && len(p) > w.N {
		p = p[:w.N]
		err = errors.New("write exceeds length")
	}
	n, err0 := w.W.Write(p)
	if err == nil {
		err = err0
	}
	w.C += int64(n)
	w.N = max(w.N-n, LengthIndefinite)
	return n, err
}

func (w *limitWriter) WriteByte(b byte) (err error) {
	if w.N != LengthIndefinite && w.Len() <= 0 {
		return errors.New("write exceeds length")
	}
	if bw, ok := w.W.(io.ByteWriter); ok {
		err = bw.WriteByte(b)
	} else {
		var n int
		n, err = w.W.Write([]byte{b})
		if n != 1 && err == nil {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		return err
	}
	w.C++
	w.N = max(w.N-1, LengthIndefinite)
	return nil
}

//endregion

//region type Encoder

// Encoder implements encoding ASN.1 types into a BER-encoded data stream. It is
// the counterpart to the [Decoder] type.
//
// To create a new Encoder, use the [NewEncoder] function.
type Encoder struct {
	w   io.Writer
	buf *bufio.Writer
}

// NewEncoder creates a new [Encoder]. Writing BER data requires single-byte
// writes. If w implements [io.ByteWriter] it is assumed to be efficient enough
// so no additional buffering is done. If w does not implement [io.ByteWriter],
// writes to w will be buffered. The buffer will be flushed after writing data
// in [Encoder.Encode] or [Encoder.EncodeWithParams].
func NewEncoder(w io.Writer) *Encoder {
	if _, ok := w.(io.Writer); ok {
		return &Encoder{w, nil}
	}
	e := &Encoder{buf: bufio.NewWriterSize(w, 512)}
	e.w = e.buf
	return e
}

// Encode writes the BER-encoding of val to its underlying writer. If encoding
// fails, an error is returned. If a value fails validation before encoding, an
// [EncodeError] will be returned.
func (e *Encoder) Encode(val any) error {
	return e.EncodeWithParams(val, "")
}

// EncodeWithParams writes the BER-encoding of val to its underlying writer. The
// format for params is described in the asn1 package. Using the `asn1:"-"`
// option has no effect here.
func (e *Encoder) EncodeWithParams(val any, params string) (err error) {
	fp := internal.ParseFieldParameters(params)
	v := reflect.ValueOf(val)
	enc, err := makeEncoder(v, fp)
	if err != nil {
		return err
	}
	if enc == nil {
		return nil
	}
	h, wt, err := encodeValue(v, enc, fp)
	if err != nil {
		return err
	}
	_, err = writeValue(v, e.w, h, wt)
	if e.buf == nil {
		return err
	}
	if fErr := e.buf.Flush(); err == nil {
		err = fErr
	}
	return err
}

//endregion

// Marshal returns the BER-encoding of val or an error if encoding fails.
func Marshal(val any) ([]byte, error) {
	return MarshalWithParams(val, "")
}

// MarshalWithParams marshals the BER-encoding of val into a byte slice and
// returns it. The format of the params is described in the asn1 package. Using
// the `asn1:"-"` option has no effect here.
func MarshalWithParams(val any, params string) ([]byte, error) {
	fp := internal.ParseFieldParameters(params)
	v := reflect.ValueOf(val)
	enc, err := makeEncoder(v, fp)
	if err != nil {
		return nil, err
	}
	if enc == nil {
		return nil, nil
	}
	h, wt, err := encodeValue(v, enc, fp)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if h.Length != LengthIndefinite {
		buf.Grow(h.Length)
	}
	_, err = writeValue(v, &buf, h, wt)
	return buf.Bytes(), err
}
