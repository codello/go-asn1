// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"slices"
	"testing"
	"time"

	"codello.dev/asn1"
)

func TestElementReader_Next(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    []Header
		wantErr error
	}{
		"SingleElement":                 {[]byte{0x02, 0x01, 0x15}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagInteger}, 1, false}}, io.EOF},
		"ChildExceedsParent":            {[]byte{0x30, 0x03, 0x02, 0x02, 0x15}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSequence}, 3, true}}, io.EOF},
		"IndefiniteLength":              {[]byte{0x30, 0x80, 0x02, 0x01, 0x15, 0x00, 0x00}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSequence}, LengthIndefinite, true}}, io.EOF},
		"UnexpectedEOF":                 {[]byte{0x30, 0x03, 0x02, 0x00}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSequence}, 3, true}}, io.ErrUnexpectedEOF},
		"UnexpectedEOFIndefiniteLength": {[]byte{0x30, 0x80, 0x30, 0x00, 0x00}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSequence}, LengthIndefinite, true}}, io.ErrUnexpectedEOF},
		"UnexpectedEndOfContents":       {[]byte{0x00, 0x00}, []Header{}, &SyntaxError{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			er := &elementReader{H: Header{Constructed: true}, R: &limitReader{bytes.NewReader(tt.data), LengthIndefinite}}
			h, _, err := er.Next()
			got := make([]Header, 0)
			for err == nil {
				got = append(got, h)
				h, _, err = er.Next()
			}
			//goland:noinspection GoErrorsAs
			if err != tt.wantErr && !errors.As(err, reflect.New(reflect.TypeOf(tt.wantErr)).Interface()) {
				t.Fatalf("Reader.Next() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Reader.Next() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestElementReader_Close(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    []Header
		wantErr error
	}{
		"SingleElement":      {[]byte{0x02, 0x01, 0x15}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagInteger}, 1, false}}, io.EOF},
		"ChildExceedsParent": {[]byte{0x30, 0x03, 0x02, 0x02, 0x15}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSequence}, 3, true}}, new(SyntaxError)},
		"InvalidChild":       {[]byte{0x30, 0x05, 0x02, 0x80, 0x15, 0x00, 0x00}, []Header{{asn1.Tag{Class: asn1.ClassUniversal, Number: asn1.TagSequence}, 5, true}}, new(SyntaxError)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			er := &elementReader{H: Header{Constructed: true}, R: &limitReader{bytes.NewReader(tt.data), LengthIndefinite}}
			h, _, err := er.Next()
			got := make([]Header, 0)
			for err == nil {
				got = append(got, h)
				if err = er.Close(); err == nil {
					h, _, err = er.Next()
				}
			}
			//goland:noinspection GoErrorsAs
			if err != tt.wantErr && !errors.As(err, reflect.New(reflect.TypeOf(tt.wantErr)).Interface()) {
				t.Fatalf("Reader.Next() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Reader.Next() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnmarshal_InvalidDecodePlain(t *testing.T) {
	data := []byte{0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}
	tests := map[string]struct {
		value any
	}{
		"Nil":          {nil},
		"NilPointer":   {(*string)(nil)},
		"NonPointer":   {""},
		"NilInterface": {new(BerDecoder)},
		"Channel":      {new(chan int)},
		"Map":          {new(map[string]string)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := Unmarshal(data, tt.value)
			if !errors.As(err, new(*InvalidDecodeError)) {
				t.Errorf("Unmarshal() error = %v, wantErr InvalidDecodeError", err)
			}
		})
	}
}

func TestUnmarshal_InvalidDecodeNested(t *testing.T) {
	data := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	tests := map[string]struct {
		value any
	}{
		"NilInterface": {&struct{ A BerDecoder }{}},
		"Channel":      {&struct{ C chan int }{}},
		"Map":          {&struct{ M map[string]string }{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := Unmarshal(data, tt.value)
			if !errors.As(err, new(*InvalidDecodeError)) {
				t.Errorf("Unmarshal() error = %v, wantErr InvalidDecodeError", err)
			}
		})
	}
}

func TestUnmarshal_Any(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want any
	}{
		"PrintableString": {[]byte{0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, "Test User 1"},
		"UTCTime":         {[]byte{0x17, 0x0d, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a}, time.Date(1991, 05, 06, 23, 45, 40, 0, time.UTC)},
		"Boolean":         {[]byte{0x01, 0x01, 0x15}, true},
		"Integer":         {[]byte{0x02, 0x01, 0x15}, 0x15},
		"BitString":       {[]byte{0x03, 0x81, 0x04, 0x06, 0x6e, 0x5d, 0xc0}, asn1.BitString{Bytes: []byte{0b01101110, 0b01011101, 0b11000000}, BitLength: 18}},
		"OID":             {[]byte{0x06, 0x05, 0x28, 0xC2, 0x7B, 0x02, 0x01}, asn1.ObjectIdentifier{1, 0, 8571, 2, 1}},
		"TagOctetString":  {[]byte{0x04, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}},
		"Null":            {[]byte{0x05, 0x81, 0x00}, nil},
		"RawValue":        {[]byte{0x48, 0x04, 0x01, 0x02, 0x03, 0x04}, RawValue{asn1.Tag{Class: asn1.ClassApplication, Number: 8}, false, []byte{0x01, 0x02, 0x03, 0x04}}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got any
			err := Unmarshal(tc.data, &got)
			if err != nil {
				t.Fatalf("Unmarshal() error = %v, want %v", err, nil)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Unmarshal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnmarshal_SliceArray(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		target  any // must be pointer type
		want    any // must be pointer type
		wantErr any
	}{
		"IntegerSlice":   {[]byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x02, 0x01, 0x02}, new([]int), &[]int{0x15, 0x02}, nil},
		"IntegerArray":   {[]byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x02, 0x01, 0x02}, new([2]int), &[2]int{0x15, 0x02}, nil},
		"TooManyValues":  {[]byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x02, 0x01, 0x02}, new([1]int), nil, &StructuralError{}},
		"TooFewValues":   {[]byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x02, 0x01, 0x02}, new([3]int), nil, &StructuralError{}},
		"NonConstructed": {[]byte{0x10, 0x03, 0x02, 0x01, 0x15}, new([]int), nil, &SyntaxError{}},
		"Empty":          {[]byte{0x30, 0x00}, new([]int), &[]int{}, nil},
		"Mixed":          {[]byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x01, 0x01, 0x00}, new([]any), &[]any{0x15, false}, nil},
		"TypeMismatch":   {[]byte{0x30, 0x03, 0x01, 0x01, 0x00}, new([1]int), nil, &StructuralError{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := Unmarshal(tt.data, tt.target)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("Unmarshal() error = %v, want %v", err, nil)
			} else if tt.wantErr != nil {
				//goland:noinspection GoErrorsAs
				if errors.As(err, reflect.New(reflect.TypeOf(tt.wantErr)).Interface()) {
					return
				}
				t.Fatalf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.target, tt.want) {
				t.Errorf("Unmarshal() = %v, want %v", tt.target, tt.want)
			}
		})
	}
}

func TestUnmarshal_Struct(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    any // also defines type for unmarshalling
		wantErr any
	}{
		"Simple":         {[]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, struct{ A, B int }{1, 2}, nil},
		"NonConstructed": {[]byte{0x10, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, struct{ A, B int }{}, &SyntaxError{}},
		"Mismatch":       {[]byte{0x30, 0x03, 0x02, 0x01, 0x01}, struct{ A, B string }{}, &StructuralError{}},
		"Optional": {[]byte{0x30, 0x03, 0x02, 0x01, 0x01}, struct {
			A string `asn1:"optional"`
			B int
		}{B: 1}, nil},
		"ForbidExtra": {[]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, struct{ A int }{A: 1}, &StructuralError{}},
		"AllowExtra": {[]byte{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03}, struct {
			A int
			asn1.Extensible
		}{A: 1}, nil},
		"Nullable": {[]byte{0x30, 0x05, 0x05, 0x00, 0x02, 0x01, 0x05}, struct {
			A *string `asn1:"nullable"`
			B int
		}{nil, 5}, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			target := reflect.New(reflect.TypeOf(tt.want))
			err := Unmarshal(tt.data, target.Interface())
			if tt.wantErr == nil && err != nil {
				t.Fatalf("Unmarshal() error = %v, want %v", err, nil)
			} else if tt.wantErr != nil {
				//goland:noinspection GoErrorsAs
				if errors.As(err, reflect.New(reflect.TypeOf(tt.wantErr)).Interface()) {
					return
				}
				t.Fatalf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(target.Elem().Interface(), tt.want) {
				t.Errorf("Unmarshal() = %v, want %v", target.Elem().Interface(), tt.want)
			}
		})
	}
}

func TestUnmarshal_IndefiniteLength(t *testing.T) {
	type test struct{ A, B int }
	testCodec(t, nil, nil, map[string]testCase[test]{
		// Unmarshal
		"Simple": {val: test{1, 2}, data: []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00}},
	})
}

func TestDecoder_Buffer(t *testing.T) {
	t.Run("FiniteLength", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00})
		// The LimitReader hides the fact that bytes.Reader is an io.ByteReader.
		d := NewDecoder(io.LimitReader(r, int64(r.Len())))
		_, er, err := d.Next()
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if err = er.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if r.Len() != 5 {
			t.Errorf("r.Len() = %d, want %d", r.Len(), 5)
		}
		_, er, err = d.Next()
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		err = er.Close()
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if r.Len() != 2 {
			t.Errorf("r.Len() = %d, want %d", r.Len(), 2)
		}
	})
	t.Run("FiniteLength", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00})
		// The LimitReader hides the fact that bytes.Reader is an io.ByteReader.
		d := NewDecoder(io.LimitReader(r, int64(r.Len())))
		_, er, err := d.Next()
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if err = er.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		var i int
		if err = d.Decode(&i); err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		if i != 1 {
			t.Errorf("d.Decode() = %d, want %d", i, 1)
		}
	})
}
