// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import "testing"

// This file contains general encoding/decoding tests not related to a specific type.

func TestCodec_Explicit(t *testing.T) {
	type appSpecificTest struct {
		A int `asn1:"explicit,tag:5"`
		B int
	}
	testCodec(t, map[string]testCase[appSpecificTest]{
		// Unmarshal
		"AppSpecific": {val: appSpecificTest{1, 2}, data: []byte{0x30, 0x08,
			0xA5, 0x03, 0x02, 0x01, 0x01,
			0x02, 0x01, 0x02}},
	}, nil, nil)
}

func TestCodec_TagOverride(t *testing.T) {
	type universalTest struct {
		A string `asn1:"universal,tag:18"`
	}
	testCodec(t, map[string]testCase[universalTest]{
		"NumericString": {val: universalTest{"1234"}, data: []byte{0x30, 0x06,
			0x12, 0x04, 0x31, 0x32, 0x33, 0x34}},
	}, nil, map[string]testCase[universalTest]{
		"InvalidType": {data: []byte{0x30, 0x06,
			0x13, 0x04, 0x31, 0x32, 0x33, 0x34}, wantErr: &StructuralError{}},
	})
}
