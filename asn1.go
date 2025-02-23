// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asn1 implements types for ASN.1 encoded data-structures as defined in
// [Rec. ITU-T X.680]. This package only defines Go types for some types defined
// by ASN.1. Encoding and decoding of data structures using different encoding
// rules is implemented in subpackages of this package.
//
// # Mapping of ASN.1 Types to Go Types
//
// Many ASN.1 types have corresponding types with the same name defined in this
// package. See the package documentation for those types for specifics about
// their limitations. Additionally, the following Go types translate into their
// ASN.1 counterparts:
//
//   - A Go bool corresponds to the ASN.1 BOOLEAN type.
//   - All Go integer types and [math/big.Int] correspond to the ASN.1 INTEGER
//     type. The supported size is limited by the Go type.
//   - The types float32 and float64 and [math/big.Float] correspond to the ASN.1
//     REAL type. The supported size is limited by the Go type.
//   - Go types with an underlying integer type correspond to the ASN.1 ENUMERATED
//     type.
//   - The Go string type corresponds to ASN.1 UTF8String type. A string can be
//     decoded from any ASN.1 string type defined in this package.
//   - A byte slice or byte array corresponds to an ASN.1 OCTET STRING. - Types
//     that implement [encoding.BinaryMarshaler] or [encoding.BinaryUnmarshaler]
//     correspond to an ASN.1 OCTET string.
//   - The type [time.Time] corresponds to the ASN.1 TIME type. A [time.Time]
//     value can be decoded from any ASN.1 time type defined in this package.
//   - Go slices and arrays correspond to the ASN.1 SEQUENCE type. Their define
//     the contents of the SEQUENCE.
//   - Go structs correspond to the ASN.1 SEQUENCE type. The struct fields define
//     the contents of the sequence, in order of definition. See the next section
//     for details.
//
// You can define your own types and use them alongside the types defined in
// this package. In order to add encoding/decoding support for a specific set of
// encoding rules, consult the corresponding package documentation for the
// encoding rules.
//
// # Defining ASN.1 Data Structures
//
// ASN.1 data can be defined via Go structs. Take the following example:
//
//	DEFINITIONS
//	IMPLICIT TAGS
//	BEGIN
//
//	MyType ::= SEQUENCE {
//		Num                  INTEGER
//		Str                  UTF8String   OPTIONAL
//		Data [APPLICATION 5] OCTET STRING
//	}
//	END
//
// This could be translated into the following Go type:
//
//	type MyType struct {
//		Num  int
//		Str  string `asn1:"optional"`
//		Data []byte `asn1:"application,tag:5"`
//	}
//
// The Go type MyType defines the contents of the ASN.1 SEQUENCE. The order in
// which the struct fields are defined, corresponds to the order of elements
// within the SEQUENCE. Struct members must use exported (upper case) names.
// Unexported members are ignored. Fields of anonymous struct members are
// treated as if they were fields of the surrounding struct. Exported members
// can be explicitly ignored by using a `asn1:"-"` struct tag. Additional
// configuration is possible via struct tags. The following struct tags are
// supported:
//
//	tag:x       specifies the ASN.1 tag number; implies ASN.1 CONTEXT SPECIFIC
//	application specifies that an APPLICATION tag is used
//	private     specifies that a PRIVATE tag is used
//	explicit    mark the element as explicit
//	optional    marks the field as ASN.1 OPTIONAL
//	omitzero    omit this field if it is a zero value
//	nullable    allows ASN.1 NULL for this element
//
// Using the struct tag `asn1:"tag:x"` (where x is a non-negative integer)
// overrides the intrinsic type of the member type. This corresponds to IMPLICIT
// TAGS in the ASN.1 syntax. By default, the tag number x is assumed to be
// CONTEXT SPECIFIC. To indicate a different class, use the "application" or
// "private" tag. The "universal" tag is supported for completeness but its use
// should be avoided as it can easily lead to invalid encodings.
//
// ASN.1 allows an element to be marked as EXPLICIT. The effect of the
// `asn1:"explicit"` tag depends on the encoding rules used. When using
// "explicit" you must also use "tag:x". Nested EXPLICIT tags cannot be
// indicated via struct tags.
//
// ASN.1 OPTIONAL elements can be marked with an `asn1:"optional"` tag. If an
// optional value is absent during decoding, no error is generated and the field
// is left unmodified. Optionality during encoding is controlled via the
// `asn1:"omitzero"` tag. If "omitzero" is present and the value for a field is
// the zero value, the field will be omitted during encoding. If a type
// implements IsZero() bool, that method is consulted, otherwise the zero value
// for its type will be used. Usually this should be paired with "optional" to
// ensure consistent encodes and decodes for a type.
//
// The `asn1:"nullable"` struct tag indicates that the type may contain an ASN.1
// NULL instead of an actual value for the type. If NULL is encountered for a
// "nullable" field, the field is set to its zero value. During encoding NULL is
// written if the field contains the zero value for its type. Usually "nullable"
// is used with pointer types.
//
// Structs can make use of the [Extensible] type to be marked as extensible.
// This corresponds to the ASN.1 extension marker. See the documentation on
// [Extensible] for details. Currently, there is no counterpart for ASN.1
// EXTENSIBILITY IMPLIED.
//
// [Rec. ITU-T X.680]: https://www.itu.int/rec/T-REC-X.680
package asn1

import (
	"strconv"
	"strings"
)

// Extensible marks a struct as extensible. It corresponds to the ASN.1
// extension marker. The Extensible type is intended to be embedded in a struct
// as an anonymous field. An extensible struct can be decoded from a
// representation that contains additional fields. For details see section 52 of
// Rec. ITU-T X.680. If a struct embeds the Extensible type, it must be the last
// non-ignored ASN.1 field, i.e. the following members must be either unexported
// or use the `asn1:"-"` struct tag.
type Extensible struct{}

// Tag constitutes an ASN.1 tag, consisting of its class and number. For
// details, see Section 8 of Rec. ITU-T X.680.
type Tag struct {
	Class  Class
	Number uint
}

// Class holds the class part of an ASN.1 tag. The class acts as a namespace for
// the tag number. A Class value is an unsigned 2-bit integer. Class values
// whose value exceeds 2 bits are invalid.
//
//go:generate stringer -type=Class -trimprefix=Class
type Class uint8

// IsValid reports whether c is a valid Class value.
func (c Class) IsValid() bool {
	return c <= 3
}

// Predefined [Class] constants. These are all the possible values that can be
// encoded in the [Class] type.
const (
	ClassUniversal Class = iota
	ClassApplication
	ClassContextSpecific
	ClassPrivate
)

// String returns a string representation t in a format similar to the one used
// in ASN.1 notation. The tag number is enclosed by square brackets and prefixed
// with the class used. To avoid ambiguity the UNIVERSAL word is used for
// universal tags, although this is not valid ASN.1 syntax.
func (t Tag) String() string {
	if t.Class == ClassContextSpecific {
		return "[" + strconv.FormatUint(uint64(t.Number), 10) + "]"
	}
	return "[" + strings.ToUpper(t.Class.String()) + " " + strconv.FormatUint(uint64(t.Number), 10) + "]"
}

// TagReserved is a reserved tag number in the [ClassUniversal] namespace to be
// used by encoding rules. This assignment is defined in Rec. ITU-T X.680,
// Section 8, Table 1.
const TagReserved = 0

// These are some ASN.1 tag numbers are defined in the [ClassUniversal]
// namespace. These assignments are defined in Rec. ITU-T X.680, Section 8, Table
// 1.
const (
	TagBoolean          uint = 1
	TagInteger          uint = 2
	TagBitString        uint = 3
	TagOctetString      uint = 4
	TagNull             uint = 5
	TagOID              uint = 6
	TagObjectDescriptor uint = 7
	TagExternal         uint = 8
	TagReal             uint = 9
	TagEnumerated       uint = 10
	TagEmbeddedPDV      uint = 11
	TagUTF8String       uint = 12
	TagRelativeOID      uint = 13
	TagTime             uint = 14
	TagSequence         uint = 16
	TagSet              uint = 17
	TagNumericString    uint = 18
	TagPrintableString  uint = 19
	TagTeletexString    uint = 20
	TagT61String             = TagTeletexString
	TagVideotexString   uint = 21
	TagIA5String        uint = 22
	TagUTCTime          uint = 23
	TagGeneralizedTime  uint = 24
	TagGraphicString    uint = 25
	TagVisibleString    uint = 26
	TagISO646String          = TagVisibleString
	TagGeneralString    uint = 27
	TagUniversalString  uint = 28
	TagCharacterString  uint = 29
	TagBMPString        uint = 30
	TagDate             uint = 31
	TagTimeOfDay        uint = 32
	TagDateTime         uint = 33
	TagDuration         uint = 34
)
