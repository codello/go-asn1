// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"codello.dev/asn1"
	"codello.dev/asn1/internal"
)

// berCodec is a helper type that combines the [BerEncoder] and [BerDecoder] types.
type berCodec interface {
	BerEncoder
	BerDecoder
}

// codec is the base type for most implementations of BER encoding and decoding
// for standard ASN.1 types. When decoding the codec contains a settable value
// reference. When encoding it contains a raw value of type T as well as a value
// reference to the same value.
//
// During decoding ref may also be a value of type interface{}.
type codec[T any] struct {
	ref reflect.Value // for decoding
	val T             // for encoding
}

// codecFor returns a codec value that can encode or decode the value in v. If
// vif is provided, it is assumed to be the result of calling v.Interface().
//
// The codec is selected mainly based on the type of vif. If vif is nil or an
// unknown type the codec is selected based on the provided tag or the
// underlying type of v.
func codecFor(v reflect.Value, vif any, tag *asn1.Tag) berCodec {
	switch vv := vif.(type) {
	case asn1.BitString:
		return bitStringCodec{v, vv}
	case int, int8, int16, int32, int64:
		return intCodec{codec: codec[any]{v, v.Int()}}
	case uint, uint8, uint16, uint32, uint64:
		return intCodec{codec: codec[any]{v, v.Uint()}}
	case big.Int:
		return bigIntCodec{v, vv}
	case asn1.Null:
		return nullCodec{v, vv}
	case asn1.ObjectIdentifier:
		return oidCodec{v, vv}
	case float32:
		return floatCodec{v, float64(vv)}
	case float64:
		return floatCodec{v, vv}
	case big.Float:
		return bigFloatCodec{v, vv}
	case asn1.UTF8String:
		return stringCodec[asn1.UTF8String]{
			tag:   asn1.TagUTF8String,
			codec: codec[asn1.UTF8String]{v, vv},
		}
	case asn1.RelativeOID:
		return relativeOIDCodec{v, vv}
	case asn1.Time:
		return timeCodec{v, vv}
	case asn1.NumericString:
		return stringCodec[asn1.NumericString]{
			tag:   asn1.TagNumericString,
			codec: codec[asn1.NumericString]{v, vv},
		}
	case asn1.PrintableString:
		return stringCodec[asn1.PrintableString]{
			tag:   asn1.TagPrintableString,
			codec: codec[asn1.PrintableString]{v, vv},
		}
	case asn1.IA5String:
		return stringCodec[asn1.IA5String]{
			tag:   asn1.TagIA5String,
			codec: codec[asn1.IA5String]{v, vv},
		}
	case asn1.VisibleString:
		return stringCodec[asn1.VisibleString]{
			tag:   asn1.TagVisibleString,
			codec: codec[asn1.VisibleString]{v, vv},
		}
	case asn1.UTCTime:
		return utcTimeCodec{v, vv}
	case asn1.GeneralizedTime:
		return generalizedTimeCodec{v, vv}
	case time.Time:
		if tag != nil && tag.Class == asn1.ClassUniversal {
			switch tag.Number {
			case asn1.TagTime:
				return timeCodec{v, asn1.Time(vv)}
			case asn1.TagUTCTime:
				return utcTimeCodec{v, asn1.UTCTime(vv)}
			case asn1.TagGeneralizedTime:
				return generalizedTimeCodec{v, asn1.GeneralizedTime(vv)}
			case asn1.TagDate:
				return dateCodec{v, asn1.Date(vv)}
			case asn1.TagTimeOfDay:
				return timeOfDayCodec{v, asn1.TimeOfDay(vv)}
			case asn1.TagDateTime:
				return dateTimeCodec{v, asn1.DateTime(vv)}
			}
		}
		return timeCodec{v, asn1.Time(vv)}
	case asn1.UniversalString:
		return universalStringCodec{v, vv}
	case asn1.BMPString:
		return bmpStringCodec{v, vv}
	case asn1.Date:
		return dateCodec{v, vv}
	case asn1.TimeOfDay:
		return timeOfDayCodec{v, vv}
	case asn1.DateTime:
		return dateTimeCodec{v, vv}
	case asn1.Duration:
		return durationCodec{v, vv}
	case time.Duration:
		return durationCodec{v, asn1.Duration(vv)}
	case Flag:
		return flagCodec{v, vv}
	case RawValue:
		return rawValueCodec{v, vv}
	}

	// s holds v.String() if v is a string
	var s string

	switch v.Kind() {
	case reflect.Bool:
		return boolCodec{v, v.Bool()}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return intCodec{true, codec[any]{v, v.Int()}}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return intCodec{true, codec[any]{v, v.Uint()}}
	case reflect.Float32, reflect.Float64:
		return floatCodec{v, v.Float()}
	case reflect.String:
		if tag == nil || tag.Class != asn1.ClassUniversal {
			tag = &asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagUTF8String}
		}
		switch tag.Number {
		case asn1.TagUTF8String,
			asn1.TagNumericString,
			asn1.TagPrintableString,
			asn1.TagIA5String,
			asn1.TagVisibleString,
			asn1.TagUniversalString,
			asn1.TagBMPString:
		default:
			tag = &asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagUTF8String}
		}
		s = v.String()
		fallthrough
	case reflect.Interface:
		// This case is only reached when decoding
		if tag.Class != asn1.ClassUniversal {
			return rawValueCodec{ref: v}
		}
		switch tag.Number {
		case asn1.TagBoolean:
			return boolCodec{ref: v}
		case asn1.TagInteger:
			return intCodec{false, codec[any]{ref: v}}
		case asn1.TagBitString:
			return bitStringCodec{ref: v}
		case asn1.TagOctetString:
			return bytesCodec{ref: v}
		case asn1.TagNull:
			return nullCodec{ref: v}
		case asn1.TagOID:
			return oidCodec{ref: v}
		case asn1.TagReal:
			return floatCodec{ref: v}
		case asn1.TagEnumerated:
			return intCodec{true, codec[any]{ref: v}}
		case asn1.TagUTF8String:
			return stringCodec[asn1.UTF8String]{
				tag:   asn1.TagUTF8String,
				codec: codec[asn1.UTF8String]{v, asn1.UTF8String(s)},
			}
		case asn1.TagRelativeOID:
			return relativeOIDCodec{ref: v}
		case asn1.TagTime:
			return timeCodec{ref: v}
		case asn1.TagNumericString:
			return stringCodec[asn1.NumericString]{
				tag:   asn1.TagNumericString,
				codec: codec[asn1.NumericString]{v, asn1.NumericString(s)},
			}
		case asn1.TagPrintableString:
			return stringCodec[asn1.PrintableString]{
				tag:   asn1.TagPrintableString,
				codec: codec[asn1.PrintableString]{v, asn1.PrintableString(s)},
			}
		case asn1.TagIA5String:
			return stringCodec[asn1.IA5String]{
				tag:   asn1.TagIA5String,
				codec: codec[asn1.IA5String]{v, asn1.IA5String(s)},
			}
		case asn1.TagVisibleString:
			return stringCodec[asn1.VisibleString]{
				tag:   asn1.TagVisibleString,
				codec: codec[asn1.VisibleString]{v, asn1.VisibleString(s)},
			}
		case asn1.TagUTCTime:
			return utcTimeCodec{ref: v}
		case asn1.TagGeneralizedTime:
			return generalizedTimeCodec{ref: v}
		case asn1.TagUniversalString:
			return universalStringCodec{v, asn1.UniversalString(s)}
		case asn1.TagBMPString:
			return bmpStringCodec{v, asn1.BMPString(s)}
		case asn1.TagDate:
			return dateCodec{ref: v}
		case asn1.TagTimeOfDay:
			return timeOfDayCodec{ref: v}
		case asn1.TagDateTime:
			return dateTimeCodec{ref: v}
		case asn1.TagDuration:
			return durationCodec{ref: v}
		default:
			return rawValueCodec{ref: v}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return bytesCodec{v, vif}
		}
	case reflect.Map:
		if v.Type().Elem() == emptyStructType {
			return setCodec{v, vif}
		}
	default:
	}
	return nil
}

// emptyStructType is used to identify the [asn1.Set] type.
var emptyStructType = reflect.TypeFor[struct{}]()

//region [UNIVERSAL 1] BOOLEAN

// boolCodec implements encoding and decoding of the ASN.1 BOOLEAN type. The
// value false is encoded as 0x00. Any other single byte value corresponds to
// true.
type boolCodec codec[bool]

func (c boolCodec) BerEncode() (h Header, w io.WriterTo, err error) {
	var bs []byte
	if c.ref.Bool() {
		bs = []byte{0xff}
	} else {
		bs = []byte{0x00}
	}
	return Header{
			Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagBoolean},
			Length:      1,
			Constructed: false},
		bytes.NewReader(bs), nil
}

func (c boolCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagBoolean}
}

func (c boolCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Len() != 1 {
		return &SyntaxError{tag, errors.New("invalid boolean")}
	}

	bt, err := r.ReadByte()
	if err != nil {
		return err
	}
	if c.ref.Kind() == reflect.Bool {
		c.ref.SetBool(bt != 0)
	} else {
		c.ref.Set(reflect.ValueOf(bt != 0))
	}
	return nil
}

//endregion

//region [UNIVERSAL 2] INTEGER and [UNIVERSAL 10] ENUMERATED

// intCodec implements encoding and decoding of the ASN.1 INTEGER and ENUMERATED
// types. All values are encoded as signed integers but encoding and decoding of
// unsigned Go integers is supported.
//
// In absence of struct tags, standard Go integer types are encoded and decoded
// as ASN.1 INTEGER and any other types with an underlying integer type is
// encoded and decoded as ENUMERATED.
//
// For large integer values see the bigIntCodec type.
type intCodec struct {
	enum bool
	codec[any]
}

func (c intCodec) BerEncode() (h Header, w io.WriterTo, err error) {
	if c.enum && c.ref.Kind() != reflect.Interface {
		if vv, ok := c.ref.Interface().(interface{ IsValid() bool }); ok && !vv.IsValid() {
			return h, nil, errors.New("invalid value for type " + c.ref.Type().String())
		}
	}
	var u64 uint64
	var signed bool
	switch c.ref.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		u64 = uint64(c.ref.Int())
		signed = true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u64 = c.ref.Uint()
		signed = false
	default:
		panic("unreachable")
	}

	var bs [9]byte
	binary.BigEndian.PutUint64(bs[1:], u64)
	l := (bits.Len64(u64) + 8 - 1) / 8
	if l == 0 {
		l = 1
	}
	if u64&(1<<63) != 0 {
		if signed {
			l -= bits.LeadingZeros64(^u64) / 8
		} else {
			l++
		}
	}
	tag := asn1.TagInteger
	if c.enum {
		tag = asn1.TagEnumerated
	}
	return Header{
			Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: tag},
			Length:      l,
			Constructed: false},
		bytes.NewReader(bs[9-l:]), nil
}

func (c intCodec) BerMatch(tag asn1.Tag) bool {
	if c.enum {
		if bm, ok := c.val.(BerMatcher); ok {
			return bm.BerMatch(tag)
		}
		return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagEnumerated}
	}
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagInteger}
}

func (c intCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Len() == 0 {
		return &SyntaxError{tag, errors.New("empty integer")}
	}
	size := int(c.ref.Type().Size())
	var signed bool
	switch c.ref.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		signed = true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		signed = false
	case reflect.Interface:
		size = bits.UintSize
		signed = true
	default:
		panic("unreachable")
	}

	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	neg := b&0x80 != 0
	val := uint64(b)
	if neg && !signed {
		return &StructuralError{tag, c.ref.Type(), errors.New("integer is signed")}
	}
	read := 1
	for r.More() && read < size {
		b, err = r.ReadByte()
		if err != nil {
			return err
		}
		read++
		val <<= 8
		val |= uint64(b)

		if read == 2 && (val&0xff80 == 0) || (val&0xff80 == 0xff80) {
			return &SyntaxError{tag, errors.New("integer not minimally-encoded")}
		} else if read == 2 && (val&0xff80 == 0x0080) && !signed {
			// Pretend our integer is larger than it is because
			// we do not need to store the leading 0x00 byte.
			size++
		}
	}
	if r.More() {
		return &StructuralError{tag, c.ref.Type(), errors.New("integer too large")}
	}

	if signed {
		i := int64(val)
		// Shift up and down in order to sign extend the result.
		i <<= 64 - read*8
		i >>= 64 - read*8
		if c.ref.Kind() == reflect.Interface && c.enum {
			c.ref.Set(reflect.ValueOf(asn1.Enumerated(i)))
		} else if c.ref.Kind() == reflect.Interface {
			c.ref.Set(reflect.ValueOf(int(i)))
		} else {
			c.ref.SetInt(i)
		}
	} else {
		c.ref.SetUint(val)
	}
	if vv, ok := c.ref.Interface().(interface{ IsValid() bool }); ok && !vv.IsValid() {
		return &StructuralError{tag, c.ref.Type(), errors.New("invalid value")}
	}
	return nil
}

var bigOne = big.NewInt(1)

// bigIntCodec implements encoding and decoding the ASN.1 INTEGER type into the
// [*math/big.Int] type. The size of the INTEGER type is not limited.
type bigIntCodec codec[big.Int]

func (c bigIntCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	h.Tag = asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagInteger}
	if c.val.Sign() == 0 {
		h.Length = 1
		// Zero is written as a single 0 zero rather than no bytes.
		wt = writerFunc(func(w io.Writer) (int64, error) {
			if err := w.(io.ByteWriter).WriteByte(0); err != nil {
				return 0, err
			}
			return 1, nil
		})
	} else if c.val.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll invert and subtract 1. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(&c.val)
		nMinus1.Sub(nMinus1, bigOne)
		bs := nMinus1.Bytes()
		for i := range bs {
			bs[i] ^= 0xff
		}
		h.Length = len(bs)
		if len(bs) == 0 || bs[0]&0x80 == 0 {
			h.Length++
			wt = writerFunc(func(w io.Writer) (int64, error) {
				if err := w.(io.ByteWriter).WriteByte(0xFF); err != nil {
					return 0, err
				}
				n, err := w.Write(bs)
				return int64(n) + 1, err
			})
		} else {
			wt = writerFunc(func(w io.Writer) (int64, error) {
				n, err := w.Write(bs)
				return int64(n), err
			})
		}
	} else {
		bs := c.val.Bytes()
		h.Length = len(bs)
		if len(bs) > 0 && bs[0]&0x80 != 0 {
			// We'll have to pad this with 0x00 in order to stop it
			// looking like a negative number.
			h.Length++
			wt = writerFunc(func(w io.Writer) (int64, error) {
				if err := w.(io.ByteWriter).WriteByte(0x00); err != nil {
					return 0, err
				}
				n, err := w.Write(bs)
				return int64(n) + 1, err
			})
		} else {
			wt = writerFunc(func(w io.Writer) (int64, error) {
				n, err := w.Write(bs)
				return int64(n), err
			})
		}
	}
	return h, wt, nil
}

func (c bigIntCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagInteger}
}

func (c bigIntCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Len() == 0 {
		return &SyntaxError{tag, errors.New("empty integer")}
	}
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("constructed INTEGER")}
	}
	bs := make([]byte, r.Len())
	if _, err := io.ReadFull(r, bs); err != nil {
		return err
	}
	// set to zero
	if len(bs) > 1 && ((bs[0] == 0x00 && bs[1]&0x80 == 0x00) || (bs[0] == 0xFF && bs[1]&0x80 == 0x80)) {
		return &SyntaxError{tag, errors.New("integer not minimally-encoded")}
	}
	i := new(big.Int)
	if bs[0]&0x80 == 0x80 {
		// negative integer, calculate 2s complement
		for i := range bs {
			bs[i] = ^bs[i]
		}
		i.SetBytes(bs)
		i.Add(i, bigOne)
		i.Neg(i)
	} else {
		i.SetBytes(bs)
	}
	c.ref.Set(reflect.ValueOf(*i))
	return nil
}

//endregion

//region [UNIVERSAL 3] BIT STRING

// bitStringCoded implements encoding and decoding of the ASN.1 BIT STRING type.
// Padding bits are encoded and decoded as zero bits. The size of the bit string
// is only limited by the size of a Go slice.
type bitStringCodec codec[asn1.BitString]

func (c bitStringCodec) BerEncode() (Header, io.WriterTo, error) {
	if !c.val.IsValid() {
		return Header{}, nil, errors.New("BitString is not valid")
	}
	h := Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagBitString},
		Length:      (c.val.BitLength+8-1)/8 + 1,
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		padding := byte((8 - c.val.BitLength%8) % 8)
		if err = w.(io.ByteWriter).WriteByte(padding); err != nil {
			return n, err
		}
		n++
		if len(c.val.Bytes) == 0 {
			return n, nil
		}
		n2, err := w.Write(c.val.Bytes[:len(c.val.Bytes)-1])
		n += int64(n2)
		if err != nil {
			return n, err
		}
		// zero out any padding bits
		b := c.val.Bytes[len(c.val.Bytes)-1] & ^byte(1<<uint(padding)-1)
		err = w.(io.ByteWriter).WriteByte(b)
		return n + 1, err
	}), nil
}

func (bitStringCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagBitString}
}

func (c bitStringCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	sr := NewStringReader(tag, r)
	var buf bytes.Buffer
	if r.Len() != LengthIndefinite {
		buf.Grow(r.Len())
	}
	var er ElementReader
	var err error
	padding := byte(0)
	for er, err = range sr.Strings() {
		if err != nil {
			break
		}
		if padding != 0 {
			err = &SyntaxError{tag, errors.New("non-zero padding in constructed BIT STRING")}
			break
		}
		if er.Len() == 0 {
			err = &SyntaxError{tag, errors.New("zero length BIT STRING")}
			break
		}
		padding, err = er.ReadByte()
		if err != nil {
			return err
		}
		if padding > 7 || er.Len() == 0 && padding > 0 {
			err = &SyntaxError{tag, errors.New("invalid padding bits in BIT STRING")}
			break
		}
		if _, err = buf.ReadFrom(er); err != nil {
			break
		}
	}
	bs := asn1.BitString{
		BitLength: int(buf.Len())*8 - int(padding),
		Bytes:     buf.Bytes(),
	}
	if err == nil && buf.Len() > 0 {
		// zero out padding bits
		bs.Bytes[len(bs.Bytes)-1] &= ^byte(1<<uint(padding) - 1)
	}
	c.ref.Set(reflect.ValueOf(bs))
	return err
}

//endregion

//region [UNIVERSAL 4] OCTET STRING

// binaryMarshalerCodec implements encoding of arbitrary Go values into an ASN.1 OCTET STRING.
// The result of the marshaler is buffered and then written to the writer.
type binaryMarshalerCodec codec[encoding.BinaryMarshaler]

func (c binaryMarshalerCodec) BerEncode() (Header, io.WriterTo, error) {
	buf, err := c.val.MarshalBinary()
	if err != nil {
		return Header{}, nil, fmt.Errorf("marshal binary: %w", err)
	}
	return Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOctetString},
		Length:      len(buf),
		Constructed: false,
	}, bytes.NewReader(buf), nil
}

// binaryUnmarshalerCodec implements decoding of an ASN.1 OCTET STRING into
// arbitrary Go values that implement [encoding.BinaryUnmarshaler]. The entire
// element is buffered into memory before the unmarshaler is invoked.
type binaryUnmarshalerCodec codec[encoding.BinaryUnmarshaler]

func (binaryUnmarshalerCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOctetString}
}

func (c binaryUnmarshalerCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	sr := NewStringReader(tag, r)
	buf, err := sr.Bytes()
	if err != nil {
		return err
	}
	return c.val.UnmarshalBinary(buf)
}

// bytesCodec implements encoding and decoding of the ASN.1 OCTET STRING type.
// Encoding and decoding can be done from and to byte slices and byte arrays.
// Pre-allocated byte slices are resliced and then reused.
type bytesCodec codec[any]

func (c bytesCodec) BerEncode() (Header, io.WriterTo, error) {
	if c.ref.Kind() == reflect.Slice || c.ref.CanAddr() {
		return Header{
			Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOctetString},
			Length:      c.ref.Len(),
			Constructed: false,
		}, bytes.NewReader(c.ref.Bytes()), nil
	}
	// unaddressable array
	h := Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOctetString},
		Length:      c.ref.Len(),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		bw := w.(io.ByteWriter)
		var n0 int
		for ; n0 < c.ref.Len() && err == nil; n0++ {
			err = bw.WriteByte(byte(c.ref.Index(n0).Uint()))
		}
		if err != nil {
			n0--
		}
		return int64(n0), err
	}), nil
}

func (bytesCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOctetString}
}

func (c bytesCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	s := NewStringReader(tag, r)
	bs, err := s.Bytes()
	if err != nil {
		return err
	}

	if c.ref.Kind() == reflect.Slice && c.ref.IsNil() {
		c.ref.SetBytes(bs)
	} else if c.ref.Kind() == reflect.Slice {
		// pre-allocated slice
		copy(c.ref.Interface().([]byte), bs)
	} else if c.ref.Kind() == reflect.Array {
		if len(bs) > c.ref.Len() {
			return &StructuralError{tag, c.ref.Type(), errors.New("too many bytes")}
		} else if len(bs) < c.ref.Len() {
			return &StructuralError{tag, c.ref.Type(), errors.New("not enough bytes")}
		}
		copy(c.ref.Slice(0, c.ref.Len()).Interface().([]byte), bs)
	} else {
		// interface{} type
		c.ref.Set(reflect.ValueOf(bs))
	}
	return err
}

//endregion

//region [UNIVERSAL 5] NULL

// nullCodec implements encoding to and decoding of the ASN.1 NULL type.
// During decoding the target value is set to its zero value.
type nullCodec codec[asn1.Null]

func (c nullCodec) BerEncode() (Header, io.WriterTo, error) {
	return Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagNull},
		Length:      0,
		Constructed: false,
	}, nil, nil
}

func (c nullCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagNull}
}

func (c nullCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Constructed() || r.Len() > 0 {
		return &SyntaxError{tag, errors.New("invalid NULL value")}
	}
	c.ref.Set(reflect.Zero(c.ref.Type()))
	return nil
}

//endregion

//region [UNIVERSAL 6] OBJECT IDENTIFIER

// oidCodec implements encoding and decoding of the ASN.1 OBJECT IDENTIFIER
// type. The first two components of the OID are encoded into a single byte.
// Subsequent components use a variable-length base128 encoding.
type oidCodec codec[asn1.ObjectIdentifier]

func (c oidCodec) BerEncode() (Header, io.WriterTo, error) {
	if len(c.val) < 2 || c.val[0] > 2 || (c.val[0] < 2 && c.val[1] > 40) {
		return Header{}, nil, errors.New("invalid asn1.ObjectIdentifier")
	}
	rel := relativeOIDCodec{val: asn1.RelativeOID(c.val[2:])}
	l := base128IntLength(c.val[0]*40 + c.val[1])
	h, wt, err := rel.BerEncode()
	if err != nil {
		return Header{}, nil, err
	}
	h2 := Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOID},
		Length:      l + h.Length,
		Constructed: false,
	}
	return h2, writerFunc(func(w io.Writer) (n int64, err error) {
		bw := w.(io.ByteWriter)
		n, err = writeBase128Int(bw, c.val[0]*40+c.val[1])
		if err != nil {
			return n, err
		}
		n0, err := wt.WriteTo(w)
		n += n0
		return n, err
	}), err
}

func (oidCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagOID}
}

func (c oidCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Len() == 0 {
		return &SyntaxError{tag, errors.New("zero length OBJECT IDENTIFIER")}
	}

	// The first varint is 40*value1 + value2:
	// According to this packing, value1 can take the values 0, 1 and 2 only.
	// When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
	// then there are no restrictions on value2.
	v, err := decodeBase128(r)
	if err != nil {
		return err
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	s := make(asn1.ObjectIdentifier, r.Len()+2)
	if v < 80 {
		s[0] = v / 40
		s[1] = v % 40
	} else {
		s[0] = 2
		s[1] = v - 80
	}
	var i int
	i, err = decodeRelativeOID(r, s[2:])
	c.ref.Set(reflect.ValueOf(s[:2+i]))
	return err
}

//endregion

//region [UNIVERSAL 9] REAL

// floatCodec implements encoding and decoding of the ASN.1 REAL type from and
// to float32 and float64.
type floatCodec codec[float64]

func (c floatCodec) BerEncode() (Header, io.WriterTo, error) {
	h := Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagReal},
		Constructed: false,
	}
	if c.val == 0 && !math.Signbit(c.val) {
		// positive zero, no content bytes
		return h, nil, nil
	} else if c.val == 0 {
		// negative zero
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000011}), nil
	} else if math.IsInf(c.val, 1) {
		// positive infinity
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000000}), nil
	} else if math.IsInf(c.val, -1) {
		// negative infinity
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000001}), nil
	} else if math.IsNaN(c.val) {
		// NaN
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000010}), nil
	}

	// compute mantissa and exponent such that the mantissa is odd
	bts := math.Float64bits(c.val)
	m := (1 << 52) | (bts & ^uint64(0xFFF<<52)) // mantissa
	e := -52 + int((bts>>52)&0x7FF) - 1023      // exponent
	shift := bits.TrailingZeros64(m)
	m >>= shift
	e += shift

	// An IEEE765 double has an exponent of 11 bits so this is either 1 or 2 bytes.
	// We are in case a) or b) of Rec. ITU-T X.690, Section 8.5.7.4.
	// In particular, we do not need an extra byte for the number of exponent bytes.
	el := ((bits.Len(uint(max(e, -e-1))) + 1) + 8 - 1) / 8
	ml := (bits.Len64(m) + 8 - 1) / 8 // mantissa is never 0
	h.Length = 1 + el + ml

	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		bw := w.(io.ByteWriter)
		s := byte(bts >> 63) // sign (1 bit)
		// First byte is 1s0000bb where s is the sign and bb is an indicator for the
		// number of octets needed for the exponent.
		if err = bw.WriteByte(0b10000000 | (s << 6) | byte(el-1)); err != nil {
			return n, err
		}
		n++
		for ; el > 0; el-- {
			if err = bw.WriteByte(byte(e >> (8 * (el - 1)))); err != nil {
				return n, err
			}
			n++
		}
		for ; ml > 0; ml-- {
			if err = bw.WriteByte(byte(m >> (8 * (ml - 1)))); err != nil {
				return n, err
			}
			n++
		}
		return n, nil
	}), nil
}

func (c floatCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagReal}
}

func (c floatCodec) BerDecode(tag asn1.Tag, r ElementReader) (err error) {
	var b byte
	var ret float64
	if r.Len() == 0 {
		ret = 0
		goto done
	}
	if b, err = r.ReadByte(); err != nil {
		return err
	}
	if b&0xC0 == 0x40 { // b == 0b01xxxxxx, this indicates a special value
		switch b {
		case 0b01000000:
			ret = math.Inf(1)
		case 0b01000001:
			ret = math.Inf(-1)
		case 0b01000010:
			ret = math.NaN()
		case 0b01000011:
			// negative 0
			ret = math.Copysign(0, -1)
		default:
			return &SyntaxError{tag, errors.New("invalid special value")}
		}
		goto done
	} else if b&0x80 == 0x80 {
		ret, err = c.parseBinary(tag, b, r)
	} else {
		ret, err = c.parseDecimal(tag, b, r)
	}
	if err != nil {
		return err
	}
done:
	if c.ref.Kind() == reflect.Interface {
		c.ref.Set(reflect.ValueOf(ret))
	} else {
		c.ref.SetFloat(ret)
	}
	return nil
}

// parseBinary parses a float from the REAL representation. b is the first byte
// of the representation, r contains the remaining bytes.
func (c floatCodec) parseBinary(tag asn1.Tag, b byte, r ElementReader) (ret float64, err error) {
	s, e, err := parseRealExp(tag, b, r)
	if err != nil {
		return 0, err
	}

	var m uint64
	b, err = r.ReadByte()
	for ; err == nil; b, err = r.ReadByte() {
		if m&(0xFF<<56) != 0 {
			if m&0xFF == 0 && e < math.MaxInt64-8 {
				m >>= 8
				e += 8
			} else {
				return 0, &SyntaxError{tag, errors.New("mantissa too large")}
			}
		}
		m = m<<8 | uint64(b)
	}
	if err != io.EOF {
		return 0, err
	}
	if m == 0 {
		return 0, &SyntaxError{tag, errors.New("zero mantissa")}
	}
	zeros := bits.LeadingZeros64(m)
	if zeros >= 11 {
		m <<= zeros - 11
	} else if bits.TrailingZeros64(m) >= 11-zeros {
		// can shift without loss in precision
		m >>= 11 - zeros
	} else {
		return 0, &SyntaxError{tag, errors.New("not enough precision")}
	}
	e += int64(11 - zeros)
	// At this point m is normalized to 52 bits plus a leading 1 in the 53rd least significant bit.
	// e contains the value that m * 2**e still calculates the value of the float.
	// We will now transform this into the IEEE754 bit pattern.

	e += 52
	if e < -1022 || e > 1023 {
		return 0, &SyntaxError{tag, errors.New("not enough precision")}
	}
	e += 1023
	val := math.Float64frombits((uint64(s) << 63) | uint64(e)<<52 | m&^(1<<52))
	if c.ref.OverflowFloat(val) {
		return 0, &SyntaxError{tag, errors.New("float32 overflow")}
	}
	return val, nil
}

// parseRealExp parses the sign and exponent of an ASN.1 REAL value. The raw
// exponent is adjusted to the base (B) and correction factor (F) in the
// encoding.
//
// See Section 8.5 of Rec. ITU-T X.690, in particular Section 8.5.7.
func parseRealExp(tag asn1.Tag, b byte, r ElementReader) (s byte, e int64, err error) {
	s = (b & 0x40) >> 6     // bit 7 of b
	base := (b & 0x30) >> 4 // bit 6 and 5 of b
	// we keep the binary code of the base for simpler computations later on
	if base > 2 {
		return s, e, &SyntaxError{tag, errors.New("invalid base")}
	}
	f := (b & 0x0C) >> 2 // bit 4 and 3 of b
	es := 1 + (b & 0x03) // bit 2 and 1 of b
	if es >= 4 {
		if b, err = r.ReadByte(); err != nil {
			return s, e, err
		}
		if b == 0 {
			return s, e, &SyntaxError{tag, errors.New("invalid exponent size")}
		}
		es = 3 + b
	}
	for i := byte(0); i < es; i++ {
		if i == 8 {
			return s, e, &SyntaxError{tag, errors.New("exponent too large")}
		}
		if b, err = r.ReadByte(); err != nil {
			return s, e, err
		}
		e = e<<8 | int64(b)
		if i == 1 && (e&0xFF80 == 0xFF80 || e&0xFF80 == 0x0000) {
			return s, e, &SyntaxError{tag, errors.New("non-minimal exponent")}
		}
	}
	// Shift up and down in order to sign extend the exponent.
	e <<= 64 - es*8
	e >>= 64 - es*8

	// float64 uses base 2.
	// Scale the exponent for other bases and apply the correction factor.
	e = e<<base + e*int64(base&0b01)
	e += int64(f)
	return s, e, err
}

// parseDecimal parses a float64 value from the decimal representation of a REAL
// value. b contains the first byte of the representation, r the remaining
// bytes.
func (c floatCodec) parseDecimal(tag asn1.Tag, b byte, r ElementReader) (float64, error) {
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return 0, err
	}
	nr := b & 0x3F
	if nr == 0 || nr > 3 {
		return 0, &SyntaxError{tag, errors.New("invalid decimal number representation")}
	}
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	s = strings.TrimLeft(s, " ")
	s = strings.Replace(s, ",", ".", 1)
	// strconv.ParseFloat accepts number that we don't so we do syntax validation
	ok := validateDecimalReal(s, nr)
	if !ok {
		return 0, &SyntaxError{tag, errors.New("invalid decimal number")}
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, &SyntaxError{tag, err}
	}
	return f, nil
}

// validateDecimalReal validates the syntax of s according to the number representation specified.
// The number representation can be NR1, NR2, or NR3, according to [ISO 6093].
//
// [ISO 6093]: https://www.iso.org/standard/12285.html
func validateDecimalReal(s string, nr byte) bool {
	if s == "" {
		return false
	}
	check := uint(^s[0]&0x04) >> 2 // 1 if s[0] == '+' or '0', 0 if s[0] == '-'
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	i := 0
	for ; i < len(s); i++ {
		if s[i] < '0' || '9' < s[i] {
			break
		}
		check += uint(s[i] & 0x0F)
	}
	if i == 0 {
		return false
	}
	s = s[i:]
	// NR1 parses only (signed) integers
	if nr == 1 || s == "" {
		return s == "" && check != 0
	}
	if s[0] != '.' && s[0] != ',' {
		goto nr3
	}
	for i = 1; i < len(s); i++ {
		if s[i] < '0' || '9' < s[i] {
			break
		}
		check += uint(s[i] & 0x0F)
	}
	s = s[i:]
nr3:
	// NR2 does not have an exponent
	if nr == 2 || len(s) < 2 {
		return s == "" && check != 0
	}
	if s[0] != 'e' && s[0] != 'E' {
		return false
	}
	s = s[1:]
	expCheck := uint(s[0]&0x02) >> 1 // 1 if s[0] == '+', 0 if s[0] == '-' or '0'
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
	}
	for i = 0; i < len(s); i++ {
		if s[i] < '0' || '9' < s[i] {
			return false
		}
		expCheck += uint(s[i] & 0x0F)
	}
	if i == 0 {
		return false
	}
	// zero exponent must have plus sign
	return check != 0 && expCheck != 0
}

// bigFloatCodec implements encoding and decoding the ASN.1 REAL type from and
// to big.Float values.
type bigFloatCodec codec[big.Float]

func (c bigFloatCodec) BerEncode() (Header, io.WriterTo, error) {
	h := Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagReal},
		Constructed: false,
	}
	zero := new(big.Float)
	if c.val.Cmp(zero) == 0 && !c.val.Signbit() {
		// positive zero, no content bytes
		return h, nil, nil
	} else if c.val.Cmp(zero) == 0 {
		// negative zero
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000011}), nil
	} else if c.val.IsInf() && !c.val.Signbit() {
		// positive infinity
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000000}), nil
	} else if c.val.IsInf() {
		// negative infinity
		h.Length = 1
		return h, bytes.NewReader([]byte{0b01000001}), nil
	}
	// big.Float cannot be NaN

	val := new(big.Float).Set(&c.val)
	// compute integer mantissa and corresponding exponent
	sign := 0
	if val.Signbit() {
		sign = 1
		val = val.Neg(val)
	}
	// using MinPrec ensures that the integer mantissa is odd
	prec := int(c.val.MinPrec())
	mant := new(big.Float)
	exp := c.val.MantExp(mant)
	iMant, _ := mant.SetMantExp(mant, prec).Int(nil)
	exp -= prec

	// calculate the number of bytes for exponent and mantissa
	el := ((bits.Len(uint(max(exp, -exp-1))) + 1) + 8 - 1) / 8
	if el-3 > 255 {
		// el-3 must fit into a byte
		return h, nil, errors.New("float too big")
	}
	ml := (iMant.BitLen() + 8 - 1) / 8 // mantissa is never 0
	h.Length = 1 + el + ml
	if el > 3 {
		h.Length++
	}

	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		bw := w.(io.ByteWriter)

		// First byte is 1s0000bb where s is the sign and bb is an indicator for the
		// number of octets needed for the exponent.
		b := byte(0b10000000 | (sign << 6))
		if el <= 3 {
			b = b | byte(el-1)
		} else {
			b = b | 0b11
		}
		if err = bw.WriteByte(b); err != nil {
			return n, err
		}
		n++
		if el > 3 {
			if err = bw.WriteByte(byte(el - 3)); err != nil {
				return n, err
			}
			n++
		}
		for ; el > 0; el-- {
			if err = bw.WriteByte(byte(exp >> (8 * (el - 1)))); err != nil {
				return n, err
			}
			n++
		}
		n0, err := w.Write(iMant.Bytes())
		n += int64(n0)
		return n, err
	}), nil
}

func (c bigFloatCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagReal}
}

func (c bigFloatCodec) BerDecode(tag asn1.Tag, r ElementReader) (err error) {
	var b byte
	var ret *big.Float
	if r.Len() == 0 {
		c.ref.Set(reflect.ValueOf(big.Float{}))
		return nil
	}
	if b, err = r.ReadByte(); err != nil {
		return err
	}
	if b&0xC0 == 0x40 { // b == 0b01xxxxxx, this indicates a special value
		switch b {
		case 0b01000000:
			ret = big.NewFloat(math.Inf(1))
		case 0b01000001:
			ret = big.NewFloat(math.Inf(-1))
		case 0b01000010:
			ret = big.NewFloat(math.NaN())
		case 0b01000011:
			// negative 0
			ret = big.NewFloat(math.Copysign(0, -1))
		default:
			return &SyntaxError{tag, errors.New("invalid special value")}
		}
	} else if b&0x80 == 0x80 {
		ret, err = c.parseBinary(tag, b, r)
	} else {
		ret, err = c.parseDecimal(tag, b, r)
	}
	if err != nil {
		return err
	}
	c.ref.Set(reflect.ValueOf(*ret))
	return nil
}

// parseBinary parses a REAL in binary representation into a big.Float.
func (c bigFloatCodec) parseBinary(tag asn1.Tag, b byte, r ElementReader) (*big.Float, error) {
	s, e, err := parseRealExp(tag, b, r)
	if err != nil {
		return nil, err
	}
	if int64(int(e)) != e {
		return nil, &SyntaxError{tag, errors.New("exponent too large")}
	}

	mbs := make([]byte, r.Len())
	if _, err = io.ReadFull(r, mbs); err != nil {
		return nil, err
	}
	m := new(big.Int).SetBytes(mbs)
	if m.Sign() == 0 {
		return nil, &SyntaxError{tag, errors.New("zero mantissa")}
	}
	ret := new(big.Float).SetMantExp(new(big.Float).SetInt(m), int(e))
	if s != 0 {
		ret.Neg(ret)
	}
	return ret, nil
}

// parseDecimal parses a REAL in decimal representation into a big.Float.
func (c bigFloatCodec) parseDecimal(tag asn1.Tag, b byte, r ElementReader) (*big.Float, error) {
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return nil, err
	}
	nr := b & 0x3F
	if nr == 0 || nr > 3 {
		return nil, &SyntaxError{tag, errors.New("invalid decimal number representation")}
	}
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	s = strings.TrimLeft(s, " ")
	s = strings.Replace(s, ",", ".", 1)
	// strconv.ParseFloat accepts number that we don't so we do syntax validation
	ok := validateDecimalReal(s, nr)
	if !ok {
		return nil, &SyntaxError{tag, errors.New("invalid decimal number")}
	}

	f, _, err := new(big.Float).SetPrec(128).Parse(s, 10)
	if err != nil {
		return nil, &SyntaxError{tag, err}
	}
	return f, nil
}

//endregion

//region [UNIVERSAL 12] UTF8String, [UNIVERSAL 18] NumericString, [UNIVERSAL 19] PrintableString, [UNIVERSAL 22] IA5String, [UNIVERSAL 26] VisibleString

// stringCodec implements encoding and decoding of various ASN.1 string types.
// String types can be decoded using either the primitive or constructed
// encoding.
//
// Strings are validated during encoding and decoding. Validation is performed
// only on the entire resulting string. In particular validation is not applied
// to individual components of constructed strings.
type stringCodec[T interface {
	~string
	IsValid() bool
}] struct {
	tag uint
	codec[T]
}

func (c stringCodec[T]) BerEncode() (h Header, w io.WriterTo, err error) {
	if !c.val.IsValid() {
		err = errors.New(c.ref.Type().String() + " contains invalid characters")
	}
	return Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: c.tag},
		Length:      len(c.val),
		Constructed: false,
	}, strings.NewReader(string(c.val)), err
}

func (c stringCodec[T]) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: c.tag}
}

func (c stringCodec[T]) BerDecode(tag asn1.Tag, r ElementReader) error {
	rs := NewStringReader(tag, r)
	var sb strings.Builder
	var buf []byte
	if r.Len() != LengthIndefinite {
		sb.Grow(r.Len())
	}
	for er, err := range rs.Strings() {
		if err != nil {
			return err
		}
		buf = slices.Grow(buf[:0], er.Len())[:er.Len()]
		_, err = io.ReadFull(er, buf)
		if err != nil {
			return err
		}
		if !T(buf).IsValid() {
			return &SyntaxError{tag, errors.New("UTF8String contains invalid characters")}
		}
		sb.Write(buf)
	}
	if c.ref.Kind() == reflect.String {
		c.ref.SetString(sb.String())
	} else {
		c.ref.Set(reflect.ValueOf(sb.String()))
	}
	return nil
}

//endregion

//region [UNIVERSAL 13] RELATIVE-OID

// relativeOIDCodec implements encoding und decoding of the ASN.1 RELATIVE-OID
// type. Every component is encoded as a variable-length base128 integer. See
// also the oidCodec type.
type relativeOIDCodec codec[asn1.RelativeOID]

func (c relativeOIDCodec) BerEncode() (Header, io.WriterTo, error) {
	l := 0
	for _, n := range c.val {
		l += base128IntLength(n)
	}
	h := Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagRelativeOID},
		Length:      l,
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		bw := w.(io.ByteWriter)
		var n2 int64
		for i := 0; i < len(c.val) && err == nil; i++ {
			n2, err = writeBase128Int(bw, c.val[i])
			n += n2
		}
		return n, nil
	}), nil
}

func (relativeOIDCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagRelativeOID}
}

func (c relativeOIDCodec) BerDecode(tag asn1.Tag, r ElementReader) (err error) {
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("primitive element")}
	}
	var s []uint
	if c.val != nil && len(c.val) >= r.Len() {
		s = c.val
	} else {
		s = make(asn1.RelativeOID, r.Len())
	}
	var i int
	i, err = decodeRelativeOID(r, s)
	c.ref.Set(reflect.ValueOf(s[:i]))
	return err
}

// decodeRelativeOID decodes OID components from r into buf. The buf must be
// large enough to hold all OID element or this method panics. The number of
// decoded OID components and any error encountered are returned.
func decodeRelativeOID(r io.ByteReader, buf []uint) (i int, err error) {
	var v uint
	for {
		v, err = decodeBase128(r)
		if err != nil {
			break
		}
		buf[i] = v
		i++
	}
	if err == io.EOF {
		err = nil
	}
	return i, err
}

//endregion

//region [UNIVERSAL 14] TIME

// timeCodec implements encoding and decoding of the ASN.1 TIME type. Values are
// encoded as their ASN.1 string representations. Sub-nanosecond precision is
// silently discarded.
//
// Currently only a subset of representable dates can be decoded.
type timeCodec codec[asn1.Time]

func (c timeCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagTime},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (c timeCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagTime}
}

func (c timeCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("constructed element")}
	}
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return err
	}
	var year, day int
	var month time.Month
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	datePart, timePart, hasTime := strings.Cut(s, "T")
	extended := false
	switch len(datePart) {
	case 7:
		year = atoiN[int](datePart, 4)
		day = atoiN[int](datePart[4:], 3)
	case 8:
		year = atoiN[int](datePart, 4)
		if datePart[4] == '-' {
			day = atoiN[int](datePart[5:], 3)
			extended = true
		} else {
			month = atoiN[time.Month](datePart[4:], 2)
			day = atoiN[int](datePart[6:], 2)
		}
	case 10:
		extended = true
		year = atoiN[int](datePart, 4)
		month = atoiN[time.Month](datePart[5:], 2)
		day = atoiN[int](datePart[8:], 2)
		if datePart[4] != '-' || datePart[7] != '-' {
			return &SyntaxError{tag, errors.New("invalid TIME")}
		}
	default:
		return &SyntaxError{tag, errors.New("invalid TIME")}
	}
	var dur time.Duration
	loc := time.Local
	if hasTime {
		var ext, ok bool
		dur, loc, ext, ok = parseISOTime(timePart)
		if !ok || extended != ext {
			return &SyntaxError{tag, errors.New("invalid TIME")}
		}
	}
	ret := time.Date(year, month, day, 0, 0, 0, 0, loc)
	if ret.Year() != year || ret.Month() != month || ret.Day() != day {
		return &SyntaxError{tag, errors.New("invalid TIME")}
	}
	ret = ret.Add(dur)

	c.ref.Set(reflect.ValueOf(ret).Convert(c.ref.Type()))
	return nil
}

func parseISOTime(s string) (time.Duration, *time.Location, bool, bool) {
	ext := len(s) > 2 && s[2] == ':'
	loc := time.Local
	var hour, minute, second, nanos time.Duration

	hour = atoiN[time.Duration](s, 2)
	s = s[2:]
	if len(s) < 2 || (ext && len(s) < 3) {
		goto tz
	}
	if ext {
		if s[0] != ':' {
			return 0, nil, false, false
		}
		s = s[1:]
	}
	minute = atoiN[time.Duration](s, 2)
	s = s[2:]
	if len(s) < 2 || (ext && len(s) < 3) {
		goto tz
	}
	if ext {
		if s[0] != ':' {
			return 0, nil, false, false
		}
		s = s[1:]
	}
	second = atoiN[time.Duration](s, 2)
	s = s[2:]

	if len(s) > 0 && (s[0] == ',' || s[0] == '.') {
		i := 1
		unit := time.Second
		for ; i < len(s); i++ {
			if s[i] < '0' || '9' < s[i] {
				break
			}
			unit /= 10
			nanos += time.Duration(s[i]-'0') * unit
		}
		if i == 1 {
			return 0, nil, false, false
		}
		s = s[i:]
	}

tz:
	if hour < 0 || minute < 0 || second < 0 {
		return 0, nil, false, false
	}
	if len(s) > 0 {
		switch s[0] {
		case 'Z':
			if len(s) != 1 {
				return 0, nil, false, false
			}
			loc = time.UTC
		case '+', '-':
			mul := 44 - int(s[0])
			if (ext && len(s) != 6) || (!ext && len(s) != 5) {
				return 0, nil, false, false
			}
			locHour := atoiN[int](s[1:], 2)
			var locMinute int
			if ext {
				if s[3] != ':' {
					return 0, nil, false, false
				}
				locMinute = atoiN[int](s[4:], 2)
			} else {
				locMinute = atoiN[int](s[3:], 2)
			}
			loc = time.FixedZone("", mul*(locHour*3600+locMinute*60))
		default:
			return 0, nil, false, false
		}
	}
	return hour*time.Hour + minute*time.Minute + second*time.Second + nanos, loc, ext, true
}

//endregion

//region [UNIVERSAL 16] SEQUENCE
// The SEQUENCE type is implemented by structDecoder, sliceDecoder, and Sequence.
//endregion

//region [UNIVERSAL 17] SET

// setCodec implements encoding and decoding of the ASN.1 SET type. Sets are
// represented in Go as maps with a value type of struct{}. During decoding the
// entire map is replaced with the decoded value. Pre-allocated maps are
// cleared.
type setCodec codec[any]

func (c setCodec) BerEncode() (Header, io.WriterTo, error) {
	seq := Sequence{Tag: asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSet}}
	for _, key := range c.ref.MapKeys() {
		if err := seq.append(key, internal.FieldParameters{}); err != nil {
			return Header{}, nil, err
		}
	}
	return seq.BerEncode()
}

func (c setCodec) BerMatch(tag asn1.Tag) bool {
	if bm, ok := c.val.(BerMatcher); ok {
		return bm.BerMatch(tag)
	}
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSet}
}

func (c setCodec) BerDecode(_ asn1.Tag, r ElementReader) (err error) {
	keyType := c.ref.Type().Key()
	empty := reflect.ValueOf(struct{}{})
	if c.ref.IsNil() {
		c.ref.Set(reflect.MakeMap(c.ref.Type()))
	} else {
		c.ref.Clear()
	}
	var (
		params internal.FieldParameters
		h      Header
		er     ElementReader
	)
	for err == nil {
		if h, er, err = r.Next(); err != nil {
			break
		}
		v := reflect.New(keyType).Elem()
		if err = decodeValue(h.Tag, er, v, params); err != nil {
			break
		}
		c.ref.SetMapIndex(v, empty)
		err = er.Close()
	}
	if err == io.EOF {
		err = nil
	}
	return err
}

//endregion

//region [UNIVERSAL 23] UTCTime

// utcTimeCodec implements encoding and decoding of the ASN.1 UTCTime type.
// Values are encoded as their ASN.1 string representation.
type utcTimeCodec codec[asn1.UTCTime]

func (c utcTimeCodec) BerEncode() (h Header, w io.WriterTo, err error) {
	if !c.val.IsValid() {
		err = errors.New("cannot represent time as UTCTime")
	}
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagUTCTime},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (utcTimeCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagUTCTime}
}

func (c utcTimeCodec) BerDecode(tag asn1.Tag, r ElementReader) (err error) {
	s, err := NewStringReader(tag, r).String()
	if err != nil {
		return err
	}
	if len(s) < 11 || len(s) > 17 {
		return &SyntaxError{tag, errors.New("invalid UTCTime")}
	}
	year := atoiN[int](s, 2)
	month := atoiN[time.Month](s[2:], 2)
	day := atoiN[int](s[4:], 2)
	hour := atoiN[int](s[6:], 2)
	minute := atoiN[int](s[8:], 2)
	s = s[10:]
	second := atoiN[int](s, 2)
	if second >= 0 {
		s = s[2:]
	} else {
		second = 0
	}
	loc := parseLocation(s)
	if loc == nil {
		return &SyntaxError{tag, errors.New("invalid UTCTime")}
	}

	// UTCTime only encodes times prior to 2050. See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
	if year < 0 {
		return &SyntaxError{tag, errors.New("invalid UTCTime")}
	} else if year <= 49 {
		year += 2000
	} else {
		year += 1900
	}
	ret := time.Date(year, month, day, hour, minute, second, 0, loc)
	if ret.Year() != year || ret.Month() != month || ret.Day() != day || ret.Hour() != hour || ret.Minute() != minute || ret.Second() != second {
		return &SyntaxError{tag, errors.New("invalid UTCTime")}
	}
	c.ref.Set(reflect.ValueOf(ret).Convert(c.ref.Type()))
	return nil
}

func parseLocation(s string) *time.Location {
	if len(s) == 1 && s[0] == 'Z' {
		return time.UTC
	}
	if len(s) != 5 {
		return nil
	}
	if s[0] != '+' && s[0] != '-' {
		return nil
	}
	mul := 44 - int(s[0])
	locHour := atoiN[int](s[1:], 2)
	locMinute := atoiN[int](s[3:], 2)
	if locHour < 0 || locMinute < 0 {
		return nil
	}
	return time.FixedZone("", mul*locHour*3600+locMinute*60)
}

func atoiN[T ~int | ~int64](s string, n int) (i T) {
	if len(s) < n {
		return -1
	}
	for j := 0; j < n; j++ {
		if s[j] < '0' || '9' < s[j] {
			return -1
		}
		i = i*10 + T(s[j]-'0')
	}
	return i
}

//endregion

//region [UNIVERSAL 24] GeneralizedTime

// generalizedTimeCodec implements encoding and decoding of the ASN.1
// GeneralizedTime type. Values are encoded as their ASN.1 string
// representations. Sub-nanosecond precision is silently discarded.
type generalizedTimeCodec codec[asn1.GeneralizedTime]

func (c generalizedTimeCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	if !c.val.IsValid() {
		err = errors.New("cannot represent time as GeneralizedTime")
	}
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagGeneralizedTime},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (c generalizedTimeCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagGeneralizedTime}
}

func (c generalizedTimeCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	s, err := NewStringReader(tag, r).String()
	if err != nil {
		return err
	}
	if len(s) < 10 {
		return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
	}
	year := atoiN[int](s, 4)
	month := atoiN[time.Month](s[4:], 2)
	day := atoiN[int](s[6:], 2)
	hour := atoiN[time.Duration](s[8:], 2)
	if hour < 0 || 23 < hour {
		return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
	}
	s = s[10:]
	dur := hour * time.Hour
	unit := time.Hour // unit for fractional time
	if len(s) >= 2 && '0' <= s[0] && s[0] <= '9' {
		minute := atoiN[time.Duration](s, 2)
		if 0 <= minute && minute <= 59 {
			dur += minute * time.Minute
			unit = time.Minute
			s = s[2:]
		} else {
			return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
		}
	}
	if len(s) >= 2 && '0' <= s[0] && s[0] <= '9' {
		second := atoiN[time.Duration](s, 2)
		if 0 <= second && second <= 59 {
			unit = time.Second
			dur += second * time.Second
			s = s[2:]
		} else {
			return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
		}
	}
	if len(s) > 0 && (s[0] == '.' || s[0] == ',') {
		i := 1
		for ; i < len(s); i++ {
			if s[i] < '0' || '9' < s[i] {
				break
			}
			unit /= 10
			dur += time.Duration(s[i]-'0') * unit
		}
		if i == 1 {
			return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
		}
		s = s[i:]
	}
	var loc *time.Location
	if len(s) == 0 {
		loc = time.Local
	} else {
		loc = parseLocation(s)
		if loc == nil {
			return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
		}
	}
	ret := time.Date(year, month, day, 0, 0, 0, 0, loc)
	ret = ret.Add(dur)
	if ret.Year() != year || ret.Month() != month || ret.Day() != day {
		return &SyntaxError{tag, errors.New("invalid GeneralizedTime")}
	}
	c.ref.Set(reflect.ValueOf(ret).Convert(c.ref.Type()))
	return nil
}

//endregion

//region [UNIVERSAL 28] UniversalString

// universalStringCodec implements encoding and decoding of the ASN.1
// UniversalString type. The encoding is UTF-32.
type universalStringCodec codec[asn1.UniversalString]

func (c universalStringCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	if !c.val.IsValid() {
		err = errors.New("UniversalString contains invalid characters")
	}
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagUniversalString},
		Length:      4 * utf8.RuneCountInString(string(c.val)),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		var n0 int
		for _, r := range c.val {
			n0, err = w.Write([]byte{byte(r >> 24), byte(r >> 16), byte(r >> 8), byte(r)})
			n += int64(n0)
			if err != nil {
				break
			}
		}
		return n, err
	}), err
}

func (universalStringCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagUniversalString}
}

func (c universalStringCodec) BerDecode(tag asn1.Tag, r ElementReader) (err error) {
	sr := NewStringReader(tag, r)
	var sb strings.Builder
	if r.Len() != LengthIndefinite {
		sb.Grow(r.Len())
	}
	for er, err := range sr.Strings() {
		if err != nil {
			return err
		}
		if er.Len()%4 != 0 {
			return &SyntaxError{tag, errors.New("length of UniversalString is no multiple of 4")}
		}
		sb.Grow(er.Len() / 4)
		for err == nil {
			var bs [4]byte
			if _, err = io.ReadFull(er, bs[:]); err != nil {
				continue
			}
			x := uint32(bs[0])<<24 | uint32(bs[1])<<16 | uint32(bs[2])<<8 | uint32(bs[3])
			if !utf8.ValidRune(rune(x)) {
				err = &SyntaxError{tag, errors.New("UniversalString contains invalid characters")}
				sb.WriteRune(utf8.RuneError)
			} else {
				sb.WriteRune(rune(x))
			}
		}
		if err != io.EOF {
			return err
		}
	}
	if c.ref.Kind() == reflect.String {
		c.ref.SetString(sb.String())
	} else {
		c.ref.Set(reflect.ValueOf(sb.String()))
	}
	return err
}

//endregion

//region [UNIVERSAL 30] BMPString

// bmpStringCodec implements encoding and decoding of the ASN.1 BMPString type.
// Values are encoded as UTF-16. Valid values are only values from the Basic
// Multilingual Plane, so very character consists of exactly two bytes.
type bmpStringCodec codec[asn1.BMPString]

func (c bmpStringCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	if !c.val.IsValid() {
		err = errors.New("BMPString contains invalid characters")
	}
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagBMPString},
		Length:      2 * utf8.RuneCountInString(string(c.val)),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (n int64, err error) {
		for _, r := range c.val {
			var n0 int
			n0, err = w.Write([]byte{byte(r >> 8), byte(r)})
			n += int64(n0)
			if err != nil {
				break
			}
		}
		return n, err
	}), err
}

func (bmpStringCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagBMPString}
}

func (c bmpStringCodec) BerDecode(tag asn1.Tag, r ElementReader) (err error) {
	sr := NewStringReader(tag, r)
	var sb strings.Builder
	if r.Len() != LengthIndefinite {
		sb.Grow(r.Len())
	}
	for er, err := range sr.Strings() {
		if err != nil {
			return err
		}
		if er.Len()%2 != 0 {
			return &SyntaxError{tag, errors.New("odd-length BMP string")}
		}
		for er.More() {
			var bs [2]byte
			if _, err = io.ReadFull(er, bs[:]); err != nil {
				return err
			}
			sb.WriteRune(rune(bs[0])<<8 | rune(bs[1]))
		}
	}
	if c.ref.Kind() == reflect.String {
		c.ref.SetString(sb.String())
	} else {
		c.ref.Set(reflect.ValueOf(sb.String()))
	}
	return nil
}

//endregion

//region [UNIVERSAL 31] DATE

// dateCodec implements encoding and decoding of the ASN.1 DATE type. Values are
// encoded as their string representations.
type dateCodec codec[asn1.Date]

func (c dateCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	if !c.val.IsValid() {
		return Header{}, nil, errors.New("invalid Date")
	}
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagDate},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (c dateCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagDate}
}

func (c dateCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("constructed element")}
	}
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return err
	}
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	var year, day int
	var month time.Month
	ok := true
	switch len(s) {
	case 8:
		year = atoiN[int](s, 4)
		month = atoiN[time.Month](s[4:], 2)
		day = atoiN[int](s[6:], 2)
	case 10:
		year = atoiN[int](s, 4)
		month = atoiN[time.Month](s[5:], 2)
		day = atoiN[int](s[8:], 2)
		ok = s[4] == '-' && s[7] == '-'
	}
	ret := time.Date(year, month, day, 0, 0, 0, 0, time.Local)
	if !ok || ret.Year() != year || ret.Month() != month || ret.Day() != day {
		return &SyntaxError{tag, errors.New("invalid DATE")}
	}
	c.ref.Set(reflect.ValueOf(ret).Convert(c.ref.Type()))
	return nil
}

//endregion

//region [UNIVERSAL 32] TIME-OF-DAY

// timeOfDayCodec implements encoding and decoding of the ASN.1 TIME-OF-DAY
// type. Values are encoded as their string representation.
type timeOfDayCodec codec[asn1.TimeOfDay]

func (c timeOfDayCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	if !c.val.IsValid() {
		return Header{}, nil, errors.New("invalid TimeOfDay")
	}
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagTimeOfDay},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (c timeOfDayCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagTimeOfDay}
}

func (c timeOfDayCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("constructed element")}
	}
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return err
	}
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	var hour, minute, second int
	ok := true
	switch len(s) {
	case 6:
		hour = atoiN[int](s, 2)
		minute = atoiN[int](s[2:], 2)
		second = atoiN[int](s[4:], 2)
	case 8:
		hour = atoiN[int](s, 2)
		minute = atoiN[int](s[3:], 2)
		second = atoiN[int](s[6:], 2)
		ok = s[2] == ':' && s[5] == ':'
	default:
		return &SyntaxError{tag, errors.New("invalid TIME-OF-DAY")}
	}
	ret := time.Date(1, 1, 1, hour, minute, second, 0, time.Local)
	if !ok || ret.Hour() != hour || ret.Minute() != minute || ret.Second() != second {
		return &SyntaxError{tag, errors.New("invalid TIME-OF-DAY")}
	}
	c.ref.Set(reflect.ValueOf(ret).Convert(c.ref.Type()))
	return nil
}

//endregion

//region [UNIVERSAL 33] DATE-TIME

// dateTimeCodec implements encoding and decoding of ASN.1 DATE-TIME values.
// Values are encoded as their string representations.
type dateTimeCodec codec[asn1.DateTime]

func (c dateTimeCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	if !c.val.IsValid() {
		return Header{}, nil, errors.New("invalid DateTime")
	}
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagDateTime},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (c dateTimeCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagDateTime}
}

func (c dateTimeCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("constructed element")}
	}
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return err
	}
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	var year, day, hour, minute, second int
	var month time.Month

	var ok bool
	switch len(s) {
	case 15:
		year = atoiN[int](s, 4)
		month = atoiN[time.Month](s[4:], 2)
		day = atoiN[int](s[6:], 2)
		hour = atoiN[int](s[9:], 2)
		minute = atoiN[int](s[11:], 2)
		second = atoiN[int](s[13:], 2)
		ok = s[8] == 'T'
	case 19:
		year = atoiN[int](s, 4)
		month = atoiN[time.Month](s[5:], 2)
		day = atoiN[int](s[8:], 2)
		hour = atoiN[int](s[11:], 2)
		minute = atoiN[int](s[14:], 2)
		second = atoiN[int](s[17:], 2)
		ok = s[4] == '-' && s[7] == '-' && s[10] == 'T' && s[13] == ':' && s[16] == ':'
	default:
		return &SyntaxError{tag, errors.New("invalid DATE-TIME")}
	}

	ret := time.Date(year, month, day, hour, minute, second, 0, time.Local)
	if !ok || ret.Year() != year || ret.Month() != month || ret.Day() != day || ret.Hour() != hour || ret.Minute() != minute || ret.Second() != second {
		return &SyntaxError{tag, errors.New("invalid DATE-TIME")}
	}
	c.ref.Set(reflect.ValueOf(ret).Convert(c.ref.Type()))
	return nil
}

//endregion

//region [UNIVERSAL 34] DURATION

// durationCodec implements encoding and decoding of the ASN.1 DURATION type.
// Values are encoded as their string representation.
type durationCodec codec[asn1.Duration]

func (c durationCodec) BerEncode() (h Header, wt io.WriterTo, err error) {
	format := c.val.String()
	h = Header{
		Tag:         asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagDuration},
		Length:      len(format),
		Constructed: false,
	}
	return h, writerFunc(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, format)
		return int64(n), err
	}), err
}

func (c durationCodec) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagDuration}
}

func (c durationCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	if r.Constructed() {
		return &SyntaxError{tag, errors.New("constructed element")}
	}
	bs := make([]byte, r.Len())
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return err
	}
	s := unsafe.String(unsafe.SliceData(bs), len(bs))
	var val time.Duration
	if len(s) == 0 {
		return &SyntaxError{tag, errors.New("invalid DURATION")}
	}
	sign := time.Duration(1)
	if s[0] == '+' || s[0] == '-' {
		sign = 44 - time.Duration(s[0])
		s = s[1:]
	}
	if !strings.HasPrefix(s, "PT") {
		return &SyntaxError{tag, errors.New("invalid DURATION")}
	}
	s = s[2:]
	unit := 2 * time.Hour
	var frac string
	for len(s) > 0 {
		if frac != "" {
			// we have content after a fractional unit
			return &SyntaxError{tag, errors.New("invalid DURATION")}
		}
		var n time.Duration
		sign := time.Duration(1)
		if s[0] == '+' || s[0] == '-' {
			sign = 44 - time.Duration(s[0])
			s = s[1:]
		}
		var i int
		for i = 0; i < len(s); i++ {
			if s[i] < '0' || '9' < s[i] {
				break
			}
			n = 10*n + time.Duration(s[i]-'0')
		}
		if len(s) > i && (s[i] == '.' || s[i] == ',') {
			i++
			j := i
			for ; i < len(s); i++ {
				if s[i] < '0' || '9' < s[i] {
					break
				}
			}
			if j == i {
				return &SyntaxError{tag, errors.New("invalid DURATION")}
			}
			frac = s[j:i]
		}
		if i == 0 || i == len(s) {
			return &SyntaxError{tag, errors.New("invalid DURATION")}
		}
		newUnit := 10 * time.Hour
		switch s[i] {
		case 'H':
			newUnit = time.Hour
		case 'M':
			newUnit = time.Minute
		case 'S':
			newUnit = time.Second
		}
		if newUnit >= unit {
			return &SyntaxError{tag, errors.New("invalid DURATION")}
		}
		unit = newUnit
		val += sign * n * unit
		for _, d := range frac {
			unit /= 10
			val += sign * time.Duration(d-'0') * unit
		}
		s = s[i+1:]
	}
	val *= sign
	c.ref.Set(reflect.ValueOf(val).Convert(c.ref.Type()))
	return nil
}

//endregion

// region type Flag

// flagCodec implements decoding the [Flag] type. Encoding the [Flag] type is
// not supported.
type flagCodec codec[Flag]

func (c flagCodec) BerDecode(_ asn1.Tag, _ ElementReader) error {
	c.ref.SetBool(true)
	return nil
}

func (flagCodec) BerEncode() (h Header, w io.WriterTo, err error) {
	return Header{}, nil, errors.New("type Flag cannot be encoded")
}

// endregion

// region type RawValue

// rawValueCodec implements encoding and decoding of the [RawValue] type.
// Matching of [RawValue] values can be restricted by setting the value before
// decoding.
//
// During decoding the contents of constructed elements are validated
// syntactically.
type rawValueCodec codec[RawValue]

func (c rawValueCodec) BerEncode() (Header, io.WriterTo, error) {
	return Header{c.val.Tag, len(c.val.Bytes), c.val.Constructed}, bytes.NewReader(c.val.Bytes), nil
}

func (c rawValueCodec) BerMatch(tag asn1.Tag) bool {
	return c.val.Tag == asn1.Tag{} || tag == c.val.Tag
}

func (c rawValueCodec) BerDecode(tag asn1.Tag, r ElementReader) error {
	rv := RawValue{
		Tag:         tag,
		Constructed: r.Constructed(),
	}
	if !r.Constructed() {
		rv.Bytes = make([]byte, r.Len())
		_, err := io.ReadFull(r, rv.Bytes)
		c.ref.Set(reflect.ValueOf(rv))
		return err
	}
	buf := bytes.Buffer{}
	if r.Len() != LengthIndefinite {
		buf.Grow(r.Len())
	}
	lr := r.(*elementReader).R
	r.(*elementReader).R = &limitReader{io.TeeReader(lr, &buf), lr.N}

	// Validate the syntax and read the element's bytes
	err := r.Close()
	rv.Bytes = buf.Bytes()
	c.ref.Set(reflect.ValueOf(rv))
	return err
}

// endregion
