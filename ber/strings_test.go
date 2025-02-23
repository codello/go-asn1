// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"
)

func TestStringReader_Read(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want []byte
	}{
		"Primitive": {[]byte{0x04, 0x03, 0x54, 0x65, 0x65}, []byte("Tee")},
		"Constructed": {[]byte{0x33, 0x0f,
			0x13, 0x05, 0x54, 0x65, 0x73, 0x74, 0x20,
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, []byte("Test " + "User 1")},
		"IndefiniteLength": {[]byte{0x33, 0x80,
			0x13, 0x05, 0x54, 0x65, 0x73, 0x74, 0x20,
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31,
			0x00, 0x00}, []byte("Test " + "User 1")},
		"EmptyString": {[]byte{0x33, 0x10,
			0x13, 0x00, // empty primitive
			0x33, 0x00, // empty constructed
			0x33, 0x80, 0x00, 0x00, // empty indefinite constructed
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, []byte("User 1")},
		"NestedConstructed": {[]byte{0x33, 0x10,
			0x33, 0x06, 0x33, 0x04, 0x13, 0x02, 0x54, 0x65,
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, []byte("TeUser 1")},
		"HeaderMismatch": {[]byte{0x33, 0x06,
			0x0C, 0x04, 0x54, 0x65, 0x73, 0x74}, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(bytes.NewReader(tc.data))
			h, er, err := d.Next()
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			r := NewStringReader(h.Tag, er)
			got, err := io.ReadAll(r)
			if tc.want == nil {
				if !errors.As(err, new(*SyntaxError)) {
					t.Errorf("Read() error = %v, wantErr %v", err, &SyntaxError{})
				}
				return
			} else if err != nil {
				t.Fatalf("Read() error = %v, wantErr nil", err)
			}
			if !bytes.Equal(tc.want, got) {
				t.Errorf("Read() got = %s, want = %s", got, tc.want)
			}
		})
	}
}

func TestStringReader_Strings(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		lens    []int
		wantErr bool
	}{
		"Primitive": {[]byte{0x04, 0x03, 0x54, 0x65, 0x65}, []int{3}, false},
		"Constructed": {[]byte{0x33, 0x0f,
			0x13, 0x05, 0x54, 0x65, 0x73, 0x74, 0x20,
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, []int{5, 6}, false},
		"IndefiniteLength": {[]byte{0x33, 0x80,
			0x13, 0x05, 0x54, 0x65, 0x73, 0x74, 0x20,
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31,
			0x00, 0x00}, []int{5, 6}, false},
		"EmptyString": {[]byte{0x33, 0x10,
			0x13, 0x00, // empty primitive
			0x33, 0x00, // empty constructed
			0x33, 0x80, 0x00, 0x00, // empty indefinite constructed
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, []int{0, 6}, false},
		"NestedConstructed": {[]byte{0x33, 0x10,
			0x33, 0x06, 0x33, 0x04, 0x13, 0x02, 0x54, 0x65,
			0x13, 0x06, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, []int{2, 6}, false},
		"HeaderMismatch": {[]byte{0x33, 0x06,
			0x0C, 0x04, 0x54, 0x65, 0x73, 0x74}, []int{}, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(bytes.NewReader(tc.data))
			h, er, err := d.Next()
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			r := NewStringReader(h.Tag, er)
			lens := make([]int, 0, len(tc.lens))
			for er, err = range r.Strings() {
				if err != nil {
					break
				}
				lens = append(lens, er.Len())
			}
			if tc.wantErr {
				if !errors.As(err, new(*SyntaxError)) {
					t.Errorf("Strings() error = %v, wantErr %v", err, &SyntaxError{})
				}
			} else if err != nil {
				t.Errorf("Strings() error = %v, wantErr nil", err)
			}
			if !slices.Equal(tc.lens, lens) {
				t.Errorf("Strings() = %v, want = %v", lens, tc.lens)
			}
		})
	}
}
