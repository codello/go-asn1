// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"codello.dev/asn1"
)

// testCase represents an encoding or decoding test case. For encoding cases
// marshaling val should result in data. For decoding cases decoding data into
// the type of val should result in val.
type testCase[T any] struct {
	val     T
	data    []byte
	params  string
	wantErr error
}

// testCodec runs the tests specified as arguments. Common tests are tested for
// both marshaling and unmarshalling. The marshal and unmarshal tests are only
// run for the respective direction.
func testCodec[T any](t *testing.T, common map[string]testCase[T], marshal map[string]testCase[T], unmarshal map[string]testCase[T]) {
	t.Helper()
	t.Run("Marshal", func(t *testing.T) {
		t.Helper()
		testMarshal[T](t, common)
		testMarshal[T](t, marshal)
	})
	t.Run("Unmarshal", func(t *testing.T) {
		t.Helper()
		testUnmarshal[T](t, common)
		testUnmarshal[T](t, unmarshal)
	})
}

// testMarshal marshals val into BER and validates that the resulting data
// matches the expectations. If tc.wantErr is nil marshaling is expected to
// generate an error of the type of tc.wantErr.
func testMarshal[T any](t *testing.T, tests map[string]testCase[T]) {
	t.Helper()
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Helper()
			got, err := MarshalWithParams(tc.val, tc.params)
			if tc.wantErr != nil {
				errTarget := reflect.New(reflect.TypeOf(tc.wantErr))
				//goland:noinspection GoErrorsAs
				if !errors.As(err, errTarget.Interface()) {
					t.Errorf("BerEncode() error = %v, wantErr = %v", err, tc.wantErr)
				}
				return
			} else if err != nil {
				t.Errorf("BerEncode() error = %v, wantErr = nil", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Errorf("BerEncode() = % X, want % X", got, tc.data)
			}
		})
	}
}

// testUnmarshal unmarshalls the provided data into type T. The result is then
// asserted against tc.val. If tc.wantErr is non-nil the unmarshalling process
// is expected to return an error of the same type as tc.wantErr.
func testUnmarshal[T any](t *testing.T, tests map[string]testCase[T]) {
	t.Helper()
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Helper()
			targetValue := reflect.New(reflect.TypeFor[T]())
			err := UnmarshalWithParams(tc.data, targetValue.Interface(), tc.params)
			got := targetValue.Elem().Interface()
			if tc.wantErr != nil {
				errTarget := reflect.New(reflect.TypeOf(tc.wantErr))
				//goland:noinspection GoErrorsAs
				if !errors.As(err, errTarget.Interface()) {
					t.Errorf("BerDecode() error = %q, wantErr = %q", err, tc.wantErr)
				}
				return
			} else if err != nil {
				t.Fatalf("BerDecode() error = %q, wantErr = nil", err)
			}
			// special case for *big.Int because reflect.DeepEqual reports false negatives
			var want any = tc.val
			if i1, ok := want.(*big.Int); ok {
				if i2, ok := got.(*big.Int); ok {
					if i1.Cmp(i2) == 0 {
						return
					}
				}
			} else if f1, ok := want.(*big.Float); ok {
				if f2, ok := got.(*big.Float); ok {
					if f1.Cmp(f2) == 0 {
						return
					}
				}
			}
			if !reflect.DeepEqual(got, tc.val) {
				t.Errorf("BerDecode() = %v, want %v", got, tc.val)
			}
		})
	}
}

// testError is an error type used for testing error cases.
type testError struct{}

func (e *testError) Error() string {
	return "test error"
}

//region [UNIVERSAL 1] BOOLEAN

func TestBoolCodec(t *testing.T) {
	testCodec(t, map[string]testCase[bool]{
		// Marshal & Unmarshal
		"True":  {val: true, data: []byte{0x01, 0x01, 0xff}},
		"False": {val: false, data: []byte{0x01, 0x01, 0x00}},
	}, nil, map[string]testCase[bool]{
		// Unmarshal
		"AnyTrue": {data: []byte{0x01, 0x01, 0xfa}, val: true},
		"Empty":   {data: []byte{0x01, 0x00}, wantErr: &SyntaxError{}},
		"TooLong": {data: []byte{0x01, 0x02, 0xff}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 2] INTEGER

func TestIntCodec(t *testing.T) {
	testCodec(t, map[string]testCase[int]{
		// Marshal & Unmarshal
		"Zero":          {val: 0, data: []byte{0x02, 0x01, 0x00}},
		"Positive":      {val: 723, data: []byte{0x02, 0x02, 0x02, 0xD3}},
		"Negative":      {val: -2, data: []byte{0x02, 0x01, 0xFE}},
		"LargeNegative": {val: -258, data: []byte{0x02, 0x02, 0xFE, 0xFE}},
	}, nil, map[string]testCase[int]{
		// Unmarshal
		"Empty":              {data: []byte{0x02, 0x00}, wantErr: &SyntaxError{}},
		"NonMinimalPositive": {data: []byte{0x02, 0x02, 0x00, 0x00}, wantErr: &SyntaxError{}},
		"NonMinimalNegative": {data: []byte{0x02, 0x02, 0xFF, 0xF2}, wantErr: &SyntaxError{}},
	})
	testCodec(t, map[string]testCase[uint]{
		// Marshal & Unmarshal
		"Uint":      {val: 827372, data: []byte{0x02, 0x03, 0x0C, 0x9F, 0xEC}},
		"LargeUint": {val: math.MaxUint64 - math.MaxInt, data: []byte{0x02, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}, nil, nil)
	testCodec(t, nil, nil, map[string]testCase[uint16]{
		// Unmarshal
		"TooLargeUint16": {data: []byte{0x02, 0x03, 0x02, 0x15, 0x51}, wantErr: &StructuralError{}},
		"SignedUint":     {data: []byte{0x02, 0x02, 0xFF, 0x51}, wantErr: &StructuralError{}},
	})
}

func TestBigIntCodec(t *testing.T) {
	testCodec(t, map[string]testCase[*big.Int]{
		// Marshal & Unmarshal
		"Zero":     {val: big.NewInt(0), data: []byte{0x02, 0x01, 0x00}},
		"Positive": {val: big.NewInt(723), data: []byte{0x02, 0x02, 0x02, 0xD3}},
		"Negative": {val: big.NewInt(-2), data: []byte{0x02, 0x01, 0xFE}},
	}, nil, map[string]testCase[*big.Int]{
		// Unmarshal
		"Empty":      {data: []byte{0x02, 0x00}, wantErr: &SyntaxError{}},
		"NonMinimal": {data: []byte{0x02, 0x02, 0x00, 0x00}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 3] BIT STRING

func TestBitStringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.BitString]{
		// Marshal & Unmarshal
		"FullByte": {val: asn1.BitString{Bytes: []byte{0xF1}, BitLength: 8}, data: []byte{0x03, 0x02, 0x00, 0xF1}},
	}, map[string]testCase[asn1.BitString]{
		// Marshal
		"HalfByte":    {val: asn1.BitString{Bytes: []byte{0xF1}, BitLength: 4}, data: []byte{0x03, 0x02, 0x04, 0xF0}},
		"PartialByte": {val: asn1.BitString{Bytes: []byte{0xF1, 0xFF}, BitLength: 9}, data: []byte{0x03, 0x03, 0x07, 0xF1, 0x80}},
	}, map[string]testCase[asn1.BitString]{
		// Unmarshal
		"SingleByte":  {data: []byte{0x03, 0x02, 0x00, 0xF1}, val: asn1.BitString{Bytes: []byte{0xF1}, BitLength: 8}},
		"HalfByte":    {data: []byte{0x03, 0x02, 0x04, 0xF1}, val: asn1.BitString{Bytes: []byte{0xF0}, BitLength: 4}},
		"PartialByte": {data: []byte{0x03, 0x03, 0x07, 0xF1, 0x8F}, val: asn1.BitString{Bytes: []byte{0xF1, 0x80}, BitLength: 9}},
		"Constructed": {data: []byte{0x23, 0x08,
			0x03, 0x02, 0x00, 0xF1,
			0x03, 0x02, 0x07, 0x8F}, val: asn1.BitString{Bytes: []byte{0xF1, 0x80}, BitLength: 9}},

		"ZeroLength":     {data: []byte{0x03, 0x00}, wantErr: &SyntaxError{}},
		"InvalidPadding": {data: []byte{0x03, 0x03, 0x09, 0xFF, 0xFF}, wantErr: &SyntaxError{}},
		"ConstructedInvalid": {data: []byte{0x23, 0x08,
			0x03, 0x02, 0x02, 0xF1,
			0x03, 0x02, 0x07, 0x8F}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 4] OCTET STRING

type binaryValue struct {
	content int16
}

func (v *binaryValue) MarshalBinary() ([]byte, error) {
	return binary.Append(nil, binary.BigEndian, v.content)
}

func (v *binaryValue) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return &testError{}
	}
	_, err := binary.Decode(data, binary.BigEndian, &v.content)
	return err
}

func TestBinaryCodec(t *testing.T) {
	testCodec(t, nil, map[string]testCase[*binaryValue]{
		// Marshal
		"Simple":  {val: &binaryValue{5}, data: []byte{0x04, 0x02, 0x00, 0x05}},
		"Simple2": {val: &binaryValue{1024}, data: []byte{0x04, 0x02, 0x04, 0x00}},
	}, map[string]testCase[*binaryValue]{
		// Unmarshal
		"Simple":    {data: []byte{0x04, 0x02, 0x00, 0x05}, val: &binaryValue{5}},
		"ShortData": {data: []byte{0x04, 0x01, 0x00}, wantErr: &testError{}},
		"Constructed": {data: []byte{0x24, 0x06,
			0x04, 0x01, 0x00,
			0x04, 0x01, 0x05}, val: &binaryValue{5}},
	})
}

func TestBytesCodec(t *testing.T) {
	testCodec(t, map[string]testCase[[]byte]{
		// Marshal & Unmarshal
		"ByteSlice": {val: []byte{0x01, 0x02}, data: []byte{0x04, 0x02, 0x01, 0x02}},
	}, nil, map[string]testCase[[]byte]{
		// Unmarshal
		"Constructed": {data: []byte{0x24, 0x06,
			0x04, 0x01, 0x01,
			0x04, 0x01, 0x02}, val: []byte{0x01, 0x02}},
	})
	testCodec(t, map[string]testCase[[2]byte]{
		// Marshal & Unmarshal
		"ByteArray": {val: [2]byte{0x01, 0x02}, data: []byte{0x04, 0x02, 0x01, 0x02}},
	}, nil, map[string]testCase[[2]byte]{
		// Unmarshal
		"ShortArray": {data: []byte{0x04, 0x03, 0x01, 0x02, 0x03}, wantErr: &StructuralError{}},
		"ShortData":  {data: []byte{0x04, 0x01, 0x01}, wantErr: &StructuralError{}},
	})
}

//endregion

//region [UNIVERSAL 5] NULL

func TestNullCodec(t *testing.T) {
	testCodec(t, nil, map[string]testCase[any]{
		// Marshal
		"AnyPointer":       {val: (*any)(nil), params: "nullable", data: []byte{0x05, 0x00}},
		"IntPointer":       {val: (*int)(nil), params: "nullable", data: []byte{0x05, 0x00}},
		"InterfacePointer": {val: (*BerEncoder)(nil), params: "nullable", data: []byte{0x05, 0x00}},
		"Null":             {val: new(asn1.Null), data: []byte{0x05, 0x00}},
	}, nil)
	// Unmarshal
	testCodec(t, nil, nil, map[string]testCase[*any]{
		"AnyPointer":   {data: []byte{0x05, 0x00}, val: nil, params: "nullable"},
		"ContentBytes": {data: []byte{0x05, 0x01, 0x01}, params: "nullable", wantErr: &SyntaxError{}},
	})
	testCodec(t, nil, nil, map[string]testCase[*int]{"IntPointer": {data: []byte{0x05, 0x00}, val: nil, params: "nullable"}})
	testCodec(t, nil, nil, map[string]testCase[*BerDecoder]{"InterfacePointer": {data: []byte{0x05, 0x00}, val: nil, params: "nullable"}})
	testCodec(t, nil, nil, map[string]testCase[asn1.Null]{
		"Null":        {data: []byte{0x05, 0x00}, val: asn1.Null{}},
		"Constructed": {data: []byte{0x25, 0x00}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 6] OBJECT IDENTIFIER

func TestObjectIdentifierCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.ObjectIdentifier]{
		// Marshal & Unmarshal
		"Regular": {val: asn1.ObjectIdentifier{1, 2, 840, 113549}, data: []byte{0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d}},
		"Minimal": {val: asn1.ObjectIdentifier{1, 2}, data: []byte{0x06, 0x01, 0x2a}},
	}, map[string]testCase[asn1.ObjectIdentifier]{
		// Marshal
		"TooShort":  {val: asn1.ObjectIdentifier{1}, wantErr: &EncodeError{}},
		"TooLarge1": {val: asn1.ObjectIdentifier{3, 2}, wantErr: &EncodeError{}},
		"TooLarge2": {val: asn1.ObjectIdentifier{1, 42}, wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.ObjectIdentifier]{
		// Unmarshal
		"TooShort":          {data: []byte{0x06, 0x00}, wantErr: &SyntaxError{}},
		"IncompleteInteger": {data: []byte{0x06, 0x02, 0x86, 0xf7}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 9] REAL

func TestFloatCodec(t *testing.T) {
	testCodec(t, map[string]testCase[float64]{
		// Marshal & Unmarshal
		"Regular":    {val: 10, data: []byte{0x09, 0x03, 0x80, 0x01, 0x05}},
		"Fractional": {val: 0.15625, data: []byte{0x09, 0x03, 0x80, 0xFB, 0x05}},
		"PosZero":    {val: 0, data: []byte{0x09, 0x00}},
		"PosInf":     {val: math.Inf(1), data: []byte{0x09, 0x01, 0x40}},
		"NegInf":     {val: math.Inf(-1), data: []byte{0x09, 0x01, 0x41}},
		"NegZero":    {val: math.Copysign(0, -1), data: []byte{0x09, 0x01, 0x43}},
	}, map[string]testCase[float64]{
		// Marshal
		"NaN": {data: []byte{0x09, 0x01, 0x42}, val: math.NaN()},
		// NaN also holds for unmarshalling, but testing is annoying because NaN != NaN.
	}, map[string]testCase[float64]{
		// Unmarshal
		"NonMinimal":        {data: []byte{0x09, 0x03, 0x80, 0x00, 0x0A}, val: 10},
		"DecimalNR1":        {data: append([]byte{0x09, 0x07, 0x01}, []byte("   -57")...), val: -57},
		"DecimalNR1Invalid": {data: append([]byte{0x09, 0x09, 0x01}, []byte("   -57.5")...), wantErr: &SyntaxError{}},
		"DecimalNR2":        {data: append([]byte{0x09, 0x06, 0x02}, []byte("+57.5")...), val: 57.5},
		"DecimalNR2Invalid": {data: append([]byte{0x09, 0x08, 0x02}, []byte("+57.5e2")...), wantErr: &SyntaxError{}},
		"DecimalNR3":        {data: append([]byte{0x09, 0x06, 0x03}, []byte("2.5e2")...), val: 2.5e2},
		"DecimalNR3Invalid": {data: append([]byte{0x09, 0x06, 0x03}, []byte("2.5e0")...), wantErr: &SyntaxError{}},
		"DecimalNR3Zero":    {data: append([]byte{0x09, 0x05, 0x03}, []byte("0e+0")...), val: 0},
	})
}

func TestBigFloatCodec(t *testing.T) {
	testCodec(t, map[string]testCase[*big.Float]{
		// Marshal & Unmarshal
		"Regular":    {val: big.NewFloat(10), data: []byte{0x09, 0x03, 0x80, 0x01, 0x05}},
		"Fractional": {val: big.NewFloat(0.15625), data: []byte{0x09, 0x03, 0x80, 0xFB, 0x05}},
		"PosZero":    {val: big.NewFloat(0), data: []byte{0x09, 0x00}},
		"PosInf":     {val: big.NewFloat(math.Inf(1)), data: []byte{0x09, 0x01, 0x40}},
		"NegInf":     {val: big.NewFloat(math.Inf(-1)), data: []byte{0x09, 0x01, 0x41}},
		"NegZero":    {val: big.NewFloat(math.Copysign(0, -1)), data: []byte{0x09, 0x01, 0x43}},
	}, map[string]testCase[*big.Float]{}, map[string]testCase[*big.Float]{
		"DecimalNR1":        {data: append([]byte{0x09, 0x07, 0x01}, []byte("   -57")...), val: big.NewFloat(-57)},
		"DecimalNR1Invalid": {data: append([]byte{0x09, 0x09, 0x01}, []byte("   -57.5")...), wantErr: &SyntaxError{}},
		"DecimalNR2":        {data: append([]byte{0x09, 0x06, 0x02}, []byte("+57.5")...), val: big.NewFloat(57.5)},
		"DecimalNR2Invalid": {data: append([]byte{0x09, 0x08, 0x02}, []byte("+57.5e2")...), wantErr: &SyntaxError{}},
		"DecimalNR3":        {data: append([]byte{0x09, 0x06, 0x03}, []byte("2.5e2")...), val: big.NewFloat(2.5e2)},
		"DecimalNR3Invalid": {data: append([]byte{0x09, 0x06, 0x03}, []byte("2.5e0")...), wantErr: &SyntaxError{}},
		"DecimalNR3Zero":    {data: append([]byte{0x09, 0x05, 0x03}, []byte("0e+0")...), val: big.NewFloat(0)},
	})
}

//endregion

//region [UNIVERSAL 10] ENUMERATED

// testEnum is a type for testing the ENUMERATED ASN.1 type.
type testEnum int

func (t testEnum) IsValid() bool {
	return t > -10 && t < 10
}

func TestEnumeratedCodec(t *testing.T) {
	testCodec(t, map[string]testCase[testEnum]{
		// Marshal & Unmarshal
		"Zero":     {val: testEnum(0), data: []byte{0x0A, 0x01, 0x00}},
		"Positive": {val: testEnum(5), data: []byte{0x0A, 0x01, 0x05}},
		"Negative": {val: testEnum(-2), data: []byte{0x0A, 0x01, 0xFE}},
	}, map[string]testCase[testEnum]{
		// Marshal
		"Invalid": {val: testEnum(-258), wantErr: &EncodeError{}},
	}, map[string]testCase[testEnum]{
		"Integer": {data: []byte{0x02, 0x01, 0x05}, wantErr: &StructuralError{}},
		"Invalid": {data: []byte{0x0A, 0x01, 0x0B}, wantErr: &StructuralError{}},
	})
}

//endregion

//region [UNIVERSAL 12] UTF8String

func TestUTF8StringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.UTF8String]{
		// Marshal & Unmarshal
		"Simple":        {val: "Hello", data: []byte{0x0C, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F}},
		"MultiByteRune": {val: "Ä", data: []byte{0x0C, 0x02, 0xC3, 0x84}},
	}, map[string]testCase[asn1.UTF8String]{
		// Marshal
		"Invalid": {val: "\xc3\x28", wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.UTF8String]{
		// Unmarshal
		"Constructed": {data: []byte{0x2C, 0x09,
			0x0C, 0x02, 0x48, 0x65,
			0x0C, 0x03, 0x6C, 0x6C, 0x6F}, val: "Hello"},
		"InvalidConstructed": {data: []byte{0x2C, 0x06,
			0x0C, 0x01, 0xC3,
			0x0C, 0x01, 0x84}, wantErr: &SyntaxError{}},
		"Invalid": {data: []byte{0x0C, 0x02, 0xc3, 0x28}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 13] RELATIVE-OID

func TestRelativeOIDCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.RelativeOID]{
		// Marshal & Unmarshal
		"Simple": {val: asn1.RelativeOID{8571, 3, 2}, data: []byte{0x0D, 0x04, 0xC2, 0x7B, 0x03, 0x02}},
		"Single": {val: asn1.RelativeOID{5}, data: []byte{0x0D, 0x01, 0x05}},
		"Empty":  {val: asn1.RelativeOID{}, data: []byte{0x0D, 0x00}},
	}, nil, map[string]testCase[asn1.RelativeOID]{
		// Unmarshal
		"IncompleteInteger": {data: []byte{0x0D, 0x02, 0x86, 0xf7}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 14] TIME

func TestTimeCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.Time]{
		"Simple":    {val: asn1.Time(time.Date(2014, 3, 12, 13, 31, 42, 200000000, time.UTC)), data: append([]byte{0x0E, 0x16}, []byte("2014-03-12T13:31:42.2Z")...)},
		"LocalTime": {val: asn1.Time(time.Date(2014, 3, 12, 13, 31, 42, 0, time.Local)), data: append([]byte{0x0E, 0x13}, []byte("2014-03-12T13:31:42")...)},
	}, nil, map[string]testCase[asn1.Time]{
		"BasicFormat": {data: append([]byte{0x0E, 0x16}, []byte("20140312T133142.2+0500")...), val: asn1.Time(time.Date(2014, 3, 12, 13, 31, 42, 200000000, time.FixedZone("", 5*3600)))},
		"MixedFormat": {data: append([]byte{0x0E, 0x19}, []byte("20140312T13:31:42.2+05:00")...), wantErr: &SyntaxError{}},
		"NoTime":      {data: append([]byte{0x0E, 0x0A}, []byte("2014-03-12")...), val: asn1.Time(time.Date(2014, 3, 12, 0, 0, 0, 0, time.Local))},
		"Invalid":     {data: append([]byte{0x0E, 0x0A}, []byte("2014-AB-CD")...), wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 17] SET

func TestSetCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.Set[int]]{
		// Marshal & Unmarshal
		"Empty": {val: asn1.NewSet[int](), data: []byte{0x31, 0x00}},
		"Single": {val: asn1.NewSet(2), data: []byte{0x31, 0x03,
			0x02, 0x01, 0x02}},
	}, map[string]testCase[asn1.Set[int]]{
		// Marshal
		"Nil": {val: nil, data: []byte{0x31, 0x00}},
	}, map[string]testCase[asn1.Set[int]]{
		"Multi": {val: asn1.NewSet(2, 4), data: []byte{0x31, 0x06,
			0x02, 0x01, 0x02,
			0x02, 0x01, 0x04}},
	})
}

//endregion

//region [UNIVERSAL 18] NumericString

func TestNumericStringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.NumericString]{
		// Marshal & Unmarshal
		"Simple": {val: "12345", data: []byte{0x12, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35}},
		"Space":  {val: "123 56", data: []byte{0x12, 0x06, 0x31, 0x32, 0x33, 0x20, 0x35, 0x36}},
	}, map[string]testCase[asn1.NumericString]{
		// Marshal
		"Invalid": {val: "Hello", wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.NumericString]{
		// Unmarshal
		"Constructed": {data: []byte{0x32, 0x0A,
			0x12, 0x03, 0x31, 0x32, 0x33,
			0x12, 0x03, 0x34, 0x35, 0x36}, val: "123456"},
		"Invalid": {data: []byte{0x12, 0x02, 0xC2, 0x7B}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 19] PrintableString

func TestPrintableStringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.PrintableString]{
		// Marshal & Unmarshal
		"Simple": {val: "Hello World", data: []byte{0x13, 0x0B, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64}},
		"Mixed":  {val: "123 (ABC)", data: []byte{0x13, 0x09, 0x31, 0x32, 0x33, 0x20, 0x28, 0x41, 0x42, 0x43, 0x29}},
	}, map[string]testCase[asn1.PrintableString]{
		// Marshal
		"Invalid": {val: "foo@bar", wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.PrintableString]{
		// Unmarshal
		"Constructed": {data: []byte{0x33, 0x0F,
			0x13, 0x06, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
			0x13, 0x05, 0x57, 0x6F, 0x72, 0x6C, 0x64}, val: "Hello World"},
		"Invalid": {data: []byte{0x13, 0x01, 0x40}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 22] IA5String

func TestIA5StringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.IA5String]{
		// Marshal & Unmarshal
		"Simple":  {val: "Hello World", data: []byte{0x16, 0x0B, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64}},
		"Mixed":   {val: "123 (ABC)", data: []byte{0x16, 0x09, 0x31, 0x32, 0x33, 0x20, 0x28, 0x41, 0x42, 0x43, 0x29}},
		"Special": {val: "foo@bar!", data: []byte{0x16, 0x08, 0x66, 0x6F, 0x6F, 0x40, 0x62, 0x61, 0x72, 0x21}},
	}, map[string]testCase[asn1.IA5String]{
		// Marshal
		"Invalid": {val: "Hällo", wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.IA5String]{
		// Unmarshal
		"Constructed": {data: []byte{0x36, 0x0F,
			0x16, 0x06, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
			0x16, 0x05, 0x57, 0x6F, 0x72, 0x6C, 0x64}, val: "Hello World"},
		"Invalid": {data: []byte{0x16, 0x01, 0x85}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 23] UTCTime

func TestUTCTimeCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.UTCTime]{
		// Marshal & Unmarshal
		"Pre2000":  {val: asn1.UTCTime(time.Date(1996, 04, 15, 20, 30, 0, 0, time.UTC)), data: []byte{0x17, 0x0D, 0x39, 0x36, 0x30, 0x34, 0x31, 0x35, 0x32, 0x30, 0x33, 0x30, 0x30, 0x30, 0x5A}},
		"Post2000": {val: asn1.UTCTime(time.Date(2045, 04, 15, 20, 30, 0, 0, time.UTC)), data: []byte{0x17, 0x0D, 0x34, 0x35, 0x30, 0x34, 0x31, 0x35, 0x32, 0x30, 0x33, 0x30, 0x30, 0x30, 0x5A}},
	}, nil, map[string]testCase[asn1.UTCTime]{
		// Unmarshal
		"NoSeconds": {data: append([]byte{0x17, 0x0B}, []byte("9604152030Z")...), val: asn1.UTCTime(time.Date(1996, 04, 15, 20, 30, 0, 0, time.UTC))},
		"Constructed": {data: []byte{0x37, 0x0F, // 9604152 + 030Z
			0x17, 0x07, 0x39, 0x36, 0x30, 0x34, 0x31, 0x35, 0x32,
			0x17, 0x04, 0x30, 0x33, 0x30, 0x5A}, val: asn1.UTCTime(time.Date(1996, 04, 15, 20, 30, 0, 0, time.UTC))},

		"Invalid":          {data: append([]byte{0x17, 0x09}, []byte("96041030Z")...), wantErr: &SyntaxError{}},
		"BeginsWithLetter": {data: append([]byte{0x17, 0x0B}, []byte("F205041030Z")...), wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 24] GeneralizedTime

func TestGeneralizedTimeCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.GeneralizedTime]{
		"Simple": {val: asn1.GeneralizedTime(time.Date(1996, 04, 15, 20, 30, 0, 0, time.UTC)), data: append([]byte{0x18, 0x0F}, []byte("19960415203000Z")...)},
	}, nil, map[string]testCase[asn1.GeneralizedTime]{
		"PartialMinutes": {data: append([]byte{0x18, 0x10}, []byte("198511062106.456")...), val: asn1.GeneralizedTime(time.Date(1985, 11, 06, 21, 06, 27, 360000000, time.Local))},
		"PartialHours":   {data: append([]byte{0x18, 0x15}, []byte("1985110621.14159-0800")...), val: asn1.GeneralizedTime(time.Date(1985, 11, 06, 21, 8, 29, 724000000, time.FixedZone("", -8*3600)))},
		"Constructed": {data: []byte{0x38, 0x19,
			0x18, 0x0A, 0x31, 0x39, 0x38, 0x38, 0x30, 0x34, 0x31, 0x35, 0x32, 0x30, // 19880415203000.0-0600
			0x18, 0x0B, 0x33, 0x30, 0x30, 0x30, 0x2E, 0x30, 0x2D, 0x30, 0x36, 0x30, 0x30}, val: asn1.GeneralizedTime(time.Date(1988, 04, 15, 20, 30, 0, 0, time.FixedZone("", -6*60*60)))},
	})
}

//endregion

//region [UNIVERSAL 26] VisibleString

func TestVisibleStringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.VisibleString]{
		// Marshal & Unmarshal
		"Simple": {val: "FTAM PCI", data: []byte{0x1A, 0x08, 0x46, 0x54, 0x41, 0x4D, 0x20, 0x50, 0x43, 0x49}},
	}, map[string]testCase[asn1.VisibleString]{
		// Marshal
		"NonVisible": {val: "Hello\nWorld", wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.VisibleString]{
		// Unmarshal
		"Constructed": {data: []byte{0x3A, 0x0C,
			0x1A, 0x05, 0x46, 0x54, 0x41, 0x4D, 0x20,
			0x1A, 0x03, 0x50, 0x43, 0x49}, val: "FTAM PCI"},
		"NonVisible": {data: []byte{0x1A, 0x08, 0x46, 0x54, 0x41, 0x4D, 0x09, 0x50, 0x43, 0x49}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 28] UniversalString

func TestUniversalStringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.UniversalString]{
		// Marshal & Unmarshal
		"SingleRune": {val: "\U000102C8", data: []byte{0x1C, 0x04, 0x00, 0x01, 0x02, 0xC8}},
	}, nil, map[string]testCase[asn1.UniversalString]{
		"Constructed": {data: []byte{0x3C, 0x0C,
			0x1C, 0x04, 0x00, 0x01, 0x02, 0xC8,
			0x1C, 0x04, 0x00, 0x01, 0x02, 0xC8}, val: "\U000102C8\U000102C8"},
		"InvalidConstructed": {data: []byte{0x3C, 0x08,
			0x1C, 0x02, 0x00, 0x01,
			0x1C, 0x02, 0x02, 0xC8}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 30] BMPString

func TestBMPStringCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.BMPString]{
		// Marshal & Unmarshal
		"SingleRune": {val: "\u0391", data: []byte{0x1E, 0x02, 0x03, 0x91}},
	}, nil, map[string]testCase[asn1.BMPString]{
		// Unmarshal
		"Constructed": {data: []byte{0x3E, 0x08,
			0x1E, 0x02, 0x03, 0x91,
			0x1E, 0x02, 0x03, 0x91}, val: "\u0391\u0391"},
		"InvalidConstructed": {data: []byte{0x3E, 0x06,
			0x1E, 0x01, 0x03,
			0x1E, 0x01, 0x91}, wantErr: &SyntaxError{}},
	})
}

//endregion

//region [UNIVERSAL 31] DATE

func TestDateCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.Date]{
		// Marshal & Unmarshal
		"Basic": {val: asn1.Date(time.Date(2014, 5, 23, 0, 0, 0, 0, time.Local)), data: append([]byte{0x1F, 0x1F, 0x0A}, []byte("2014-05-23")...)},
	}, map[string]testCase[asn1.Date]{
		// Marshal
		"WithTime": {val: asn1.Date(time.Date(2014, 5, 23, 5, 2, 1, 5, time.UTC)), wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.Date]{
		// Unmarshal
		"BasicForm": {data: append([]byte{0x1F, 0x1F, 0x08}, []byte("20140523")...), val: asn1.Date(time.Date(2014, 5, 23, 0, 0, 0, 0, time.Local))},
	})
}

//endregion

//region [UNIVERSAL 32] TIME-OF-DAY

func TestTimeOfDayCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.TimeOfDay]{
		// Marshal & Unmarshal
		"Basic": {val: asn1.TimeOfDay(time.Date(1, 1, 1, 15, 12, 3, 0, time.Local)), data: append([]byte{0x1F, 0x20, 0x08}, []byte("15:12:03")...)},
	}, map[string]testCase[asn1.TimeOfDay]{
		// Marshal
		"IgnoreDate": {val: asn1.TimeOfDay(time.Date(2015, 5, 12, 15, 12, 3, 0, time.Local)), wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.TimeOfDay]{
		// Unmarshal
		"BasicForm": {val: asn1.TimeOfDay(time.Date(1, 1, 1, 15, 12, 3, 0, time.Local)), data: append([]byte{0x1F, 0x20, 0x06}, []byte("151203")...)},
	})
}

//endregion

//region [UNIVERSAL 33] DATE-TIME

func TestDateTimeCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.DateTime]{
		// Marshal & Unmarshal
		"Basic": {val: asn1.DateTime(time.Date(2019, 8, 29, 15, 12, 3, 0, time.Local)), data: append([]byte{0x1F, 0x21, 0x13}, []byte("2019-08-29T15:12:03")...)},
	}, map[string]testCase[asn1.DateTime]{
		// Marshal
		"IgnoreLocation": {val: asn1.DateTime(time.Date(2019, 8, 29, 15, 12, 3, 0, time.UTC)), wantErr: &EncodeError{}},
	}, map[string]testCase[asn1.DateTime]{
		// Unmarshal
		"BasicForm": {val: asn1.DateTime(time.Date(2019, 8, 29, 15, 12, 3, 0, time.Local)), data: append([]byte{0x1F, 0x21, 0x0F}, []byte("20190829T151203")...)},
	})
}

//endregion

//region [UNIVERSAL 34] DURATION

func TestDurationCodec(t *testing.T) {
	testCodec(t, map[string]testCase[asn1.Duration]{
		// Marshal & Unmarshal
		"Zero":           {val: asn1.Duration(0), data: append([]byte{0x1F, 0x22, 0x04}, []byte("PT0S")...)},
		"Hour":           {val: asn1.Duration(time.Hour), data: append([]byte{0x1F, 0x22, 0x04}, []byte("PT1H")...)},
		"Minute":         {val: asn1.Duration(time.Minute), data: append([]byte{0x1F, 0x22, 0x04}, []byte("PT1M")...)},
		"Second":         {val: asn1.Duration(time.Second), data: append([]byte{0x1F, 0x22, 0x04}, []byte("PT1S")...)},
		"Mixed":          {val: asn1.Duration(2*time.Hour + 12*time.Minute + 5*time.Second), data: append([]byte{0x1F, 0x22, 0x09}, []byte("PT2H12M5S")...)},
		"Negative":       {val: asn1.Duration(-2*time.Hour - 15*time.Minute - 4*time.Second), data: append([]byte{0x1F, 0x22, 0x0A}, []byte("-PT2H15M4S")...)},
		"PartialSeconds": {val: asn1.Duration(2*time.Hour + 15*time.Second + 15*time.Millisecond), data: append([]byte{0x1F, 0x22, 0x0B}, []byte("PT2H15.015S")...)},
	}, nil, map[string]testCase[asn1.Duration]{
		// Unmarshal
		"UnitOverflow":    {data: append([]byte{0x1F, 0x22, 0x0B}, []byte("PT2H62M120S")...), val: asn1.Duration(2*time.Hour + 62*time.Minute + 120*time.Second)},
		"PartialNegative": {data: append([]byte{0x1F, 0x22, 0x0B}, []byte("PT2H-32M18S")...), val: asn1.Duration(2*time.Hour - 32*time.Minute + 18*time.Second)},
		"PartialPositive": {data: append([]byte{0x1F, 0x22, 0x0C}, []byte("-PT2H-32M18S")...), val: asn1.Duration(-(2*time.Hour - 32*time.Minute + 18*time.Second))},
		"InvalidPartial":  {data: append([]byte{0x1F, 0x22, 0x0D}, []byte("PT2H15.015M7S")...), wantErr: &SyntaxError{}},
	})
}

//endregion

//region type Flag

func TestFlag(t *testing.T) {
	var data struct {
		A int
		B Flag `asn1:"optional"`
	}
	t.Run("Absent", func(t *testing.T) {
		err := Unmarshal([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, &data)
		if err != nil {
			t.Fatalf("BerDecode() error = %v, wantErr %v", err, nil)
		}
		if data.B != false {
			t.Errorf("BerDecode() = %v, want %v", data.B, false)
		}
	})
	t.Run("Present", func(t *testing.T) {
		err := Unmarshal([]byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}, &data)
		if err != nil {
			t.Fatalf("BerDecode() error = %v, wantErr %v", err, nil)
		}
		if data.B != true {
			t.Errorf("BerDecode() = %v, want %v", data.B, true)
		}
	})
}

//endregion

//region type RawValue

func TestRawValue(t *testing.T) {
	testCodec(t, map[string]testCase[*RawValue]{
		"Primitive":   {val: &RawValue{asn1.ClassApplication | 6, false, []byte{0x01, 0x02}}, data: []byte{0x46, 0x02, 0x01, 0x02}},
		"Constructed": {val: &RawValue{asn1.ClassApplication | 6, true, []byte{0x02, 0x01, 0x02}}, data: []byte{0x66, 0x03, 0x02, 0x01, 0x02}},
	}, nil, map[string]testCase[*RawValue]{
		"InvalidConstructed": {data: []byte{0x66, 0x02, 0x01, 0x02}, wantErr: &SyntaxError{}},
	})
}

//endregion
