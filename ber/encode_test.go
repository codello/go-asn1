// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"testing"
)

func TestMarshal(t *testing.T) {
	tests := map[string]struct {
		val  any
		want []byte
	}{
		"Simple":  {5, []byte{0x02, 0x01, 0x05}},
		"Slice":   {[]int{1, 2}, []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}},
		"String":  {"Test User 1", []byte{0x0C, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}},
		"Boolean": {false, []byte{0x01, 0x01, 0x00}},
		"Struct":  {struct{ A, B int }{5, 6}, []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06}},
		"Explicit": {struct {
			A int `asn1:"explicit,tag:2"`
		}{2}, []byte{0x30, 0x05, 0xA2, 0x03, 0x02, 0x01, 0x02}},
		"OmitZero": {struct {
			B string `asn1:"omitzero"`
			A int
		}{"", 6}, []byte{0x30, 0x03, 0x02, 0x01, 0x06}},
		"Nullable": {struct {
			A string `asn1:"nullable"`
			B *int   `asn1:"nullable"`
			C int    `asn1:"nullable,omitzero"`
		}{"", nil, 5}, []byte{0x30, 0x07, 0x05, 0x00, 0x05, 0x00, 0x02, 0x01, 0x05}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Marshal(tt.val)
			if err != nil {
				t.Fatalf("Marshal() error = %v, want nil", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Marshal() = % X, want % X", string(got), string(tt.want))
			}
		})
	}
}
