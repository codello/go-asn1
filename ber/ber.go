// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ber implements the ASN.1 Basic Encoding Rules (BER). The Basic
// Encoding Rules are defined in [Rec. ITU-T X.690].
// See also “[A Layman's Guide to a Subset of ASN.1, BER, and DER]”.
//
// See the package documentation of the asn1 package for details how Go types
// translate to ASN.1 types. Types following that specification can be encoded
// into and decoded from a stream of binary data using the Basic Encoding Rules
// using this package. The following limitations apply:
//
//   - When decoding an ASN.1 INTEGER type into a Go integer the size of the
//     integer is limited by the size of the Go type. This limitation does not apply
//     to [*math/big.Int].
//   - When decoding an ASN.1 REAL type into a Go float64 or float32, the size of
//     the value is limited by the size of the Go type. When using [*math/big.Float]
//     the size limitations of that type apply.
//   - When decoding binary data into a pre-allocated byte slice the data will
//     overwrite existing data in the slice.
//   - When decoding binary data into a byte array, the number of bytes in the
//     element must match the length of the array exactly.
//   - When decoding a constructed element into an array the number of sequence
//     elements must match the length of the array exactly.
//   - Decoding into an interface{} will decode known types as their corresponding
//     Go values. Unrecognized types will be stored as [RawValue].
//
// [Rec. ITU-T X.690]: https://www.itu.int/rec/T-REC-X.690
// [A Layman's Guide to a Subset of ASN.1, BER, and DER]: http://luca.ntop.org/Teaching/Appunti/asn1.html
package ber

import (
	"fmt"

	"codello.dev/asn1"
)

// A Flag accepts any data and is set to true if present. A flag cannot be
// encoded into BER. In most cases a Flag should be used on an optional element.
type Flag bool

// A RawValue represents an un-decoded ASN.1 object. During decoding the syntax
// of structured elements is validated so the Bytes are guaranteed to contain a
// valid BER encoding. During encoding the bytes are written as-is without any
// validation.
type RawValue struct {
	Tag         asn1.Tag
	Constructed bool
	Bytes       []byte
}

// String returns a string representation of rv. The byte contents of rv are
// only included if they are short enough.
func (rv RawValue) String() string {
	constructed := "primitive"
	if rv.Constructed {
		constructed = "constructed"
	}
	if len(rv.Bytes) > 24 {
		return fmt.Sprintf("RawValue{%s (%s) {%d bytes}}", rv.Tag.String(), constructed, len(rv.Bytes))
	}
	return fmt.Sprintf("RawValue{%s (%s) {% X}}", rv.Tag.String(), constructed, rv.Bytes)
}
