// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strconv"
	"testing"

	"codello.dev/asn1"
)

func TestHeader_encode(t *testing.T) {
	tests := map[string]struct {
		Header
		want []byte
	}{
		"EndOfContents":      {Header{asn1.TagReserved, 0, false}, []byte{0x00, 0x00}},
		"UTF8String":         {Header{asn1.TagUTF8String, 5, false}, []byte{0x0C, 0x05}},
		"LongTag":            {Header{asn1.ClassContextSpecific | 173, 8, true}, []byte{0xBF, 0x81, 0x2D, 0x08}},
		"Sequence":           {Header{asn1.TagSequence, 60, true}, []byte{0x30, 60}},
		"LongSequence":       {Header{asn1.TagSequence, 746, true}, []byte{0x30, 0x80 | 0x02, 0x02, 0xEA}},
		"IndefiniteSequence": {Header{asn1.TagSequence, LengthIndefinite, true}, []byte{0x30, 0x80}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			hLen := tt.Header.numBytes()
			if got := hLen; got != len(tt.want) {
				t.Errorf("numBytes() = %v, want %v", got, len(tt.want))
			}
			var buf bytes.Buffer
			buf.Grow(hLen)
			n, err := tt.Header.writeTo(&buf)
			if err != nil {
				t.Errorf("encode() = error = %v, want nil", err)
			}
			if n != int64(len(tt.want)) {
				t.Errorf("encode() = %d, want %d", n, hLen)
			}
			if got := buf.Bytes(); !slices.Equal(tt.want, got) {
				t.Errorf("encode() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestHeader_decode(t *testing.T) {
	tests := map[string]struct {
		data       []byte
		extraBytes int
		want       Header
		wantErr    error
	}{
		"EndOfContents":      {[]byte{0x00, 0x00}, 0, Header{asn1.TagReserved, 0, false}, nil},
		"UTF8String":         {[]byte{0x0C, 0x05, 0x00}, 1, Header{asn1.TagUTF8String, 5, false}, nil},
		"LongTag":            {[]byte{0xBF, 0x81, 0x2D, 0x08, 0x00, 0x00}, 2, Header{asn1.ClassContextSpecific | 173, 8, true}, nil},
		"Sequence":           {[]byte{0x30, 60}, 0, Header{asn1.TagSequence, 60, true}, nil},
		"LongSequence":       {[]byte{0x30, 0x80 | 0x02, 0x02, 0xEA}, 0, Header{asn1.TagSequence, 746, true}, nil},
		"IndefiniteSequence": {[]byte{0x30, 0x80}, 0, Header{asn1.TagSequence, LengthIndefinite, true}, nil},

		"EOF":            {nil, 0, Header{}, io.EOF},
		"ErrNoLength":    {[]byte{0x30}, 0, Header{}, io.ErrUnexpectedEOF},
		"ErrShortTag":    {[]byte{0xBF, 0x81, 0x2D}, 0, Header{}, io.ErrUnexpectedEOF},
		"ErrShortLength": {[]byte{0x30, 0x80 | 0x02, 0x02}, 0, Header{}, io.ErrUnexpectedEOF},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := decodeHeader(r)
			if err != tt.wantErr {
				t.Fatalf("decodeHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("decodeHeader() = %v, want %v", got, tt.want)
			}
			if r.Len() != tt.extraBytes {
				t.Errorf("decodeHeader() extra bytes = %d, want %d", r.Len(), tt.extraBytes)
			}
		})
	}
}

func Test_encodeBase128Int(t *testing.T) {
	tests := []struct {
		value uint
		want  []byte
	}{
		{0, []byte{0x00}},
		{25, []byte{25}},
		{641, []byte{0x85, 0x01}},
	}
	for _, tt := range tests {
		t.Run(strconv.FormatUint(uint64(tt.value), 10), func(t *testing.T) {
			l := base128IntLength(tt.value)
			if l != len(tt.want) {
				t.Errorf("base128IntLength() = %d, want %d", l, len(tt.want))
			}
			var buf bytes.Buffer
			buf.Grow(l)
			n, err := writeBase128Int(&buf, tt.value)
			if err != nil {
				t.Fatalf("writeBase128Int(%v) error = %v, want nil", tt.value, err)
			}
			if n != int64(len(tt.want)) {
				t.Errorf("writeBase128Int(%v) n = %d, want %d", tt.value, n, len(tt.want))
			}
			if got := buf.Bytes(); !slices.Equal(got, tt.want) {
				t.Errorf("writeBase128Int(%v) = % X, want % X", tt.value, got, tt.want)
			}
		})
	}
}

func Test_decodeBase128(t *testing.T) {
	tests := map[string]struct {
		data       []byte
		extraBytes int
		want       uint
		wantErr    error
	}{
		"SingleByte":    {[]byte{0x05}, 0, 5, nil},
		"MultiByte":     {[]byte{0x85, 0x01, 0x00}, 1, 641, nil},
		"EOF":           {nil, 0, 0, io.EOF},
		"UnexpectedEOF": {[]byte{0x81, 0x80}, 0, 0, io.ErrUnexpectedEOF},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := decodeBase128(r)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("decodeBase128() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("decodeBase128() got = %v, want %v", got, tt.want)
			}
			if r.Len() != tt.extraBytes {
				t.Errorf("decodeBase128() extra bytes = %d, want %d", r.Len(), tt.extraBytes)
			}
		})
	}

	// test syntax errors
	tests2 := map[string][]byte{
		"NonMinimal": {0x80, 0x85, 0x01},
		"Overflow":   {0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, // assumes uint size of 8 bytes (64 bit architecture)
	}
	for name, tt := range tests2 {
		t.Run(name, func(t *testing.T) {
			_, err := decodeBase128(bytes.NewReader(tt))
			if err == nil {
				t.Errorf("decodeBase128() error = %v, want err", err)
			}
		})
	}
}
