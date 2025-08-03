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
// which the struct fields are defined, corresponds to the order of data values
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
//	explicit    mark the field as explicit
//	optional    marks the field as ASN.1 OPTIONAL
//	omitzero    omit this field if it is a zero value
//	nullable    allows ASN.1 NULL for this data value
//
// Using the struct tag `asn1:"tag:x"` (where x is a non-negative integer)
// overrides the intrinsic type of the member type. This corresponds to IMPLICIT
// TAGS in the ASN.1 syntax. By default, the tag number x is assumed to be
// CONTEXT SPECIFIC. To indicate a different class, use the "application" or
// "private" tag. The "universal" tag is supported for completeness but its use
// should be avoided as it can easily lead to invalid encodings.
//
// ASN.1 allows a subtype to be marked as EXPLICIT. The effect of the
// `asn1:"explicit"` tag depends on the encoding rules used. When using
// "explicit" you must also use "tag:x". Nested EXPLICIT tags cannot be
// indicated via struct tags.
//
// ASN.1 OPTIONAL types can be marked with an `asn1:"optional"` tag. If a value
// for an optional type is absent during decoding, no error is generated and the
// field is left unmodified. Optionality during encoding is controlled via the
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
// [Extensible] for details.
//
// # Limitations
//
// Currently the ASN.1 CHOICE type is not explicitly supported. Support can be
// added by implementing custom encoding and decoding strategies for types
// containing CHOICE components.
//
// [Rec. ITU-T X.680]: https://www.itu.int/rec/T-REC-X.680
package asn1

import (
	"strconv"
)

// Extensible marks a struct as extensible. It corresponds to the ASN.1
// extension marker. The Extensible type is intended to be embedded in a struct
// as an anonymous field. An extensible struct can be decoded from a
// representation that contains additional fields. For details see section 52 of
// Rec. ITU-T X.680. If a struct embeds the Extensible type, it must be the last
// non-ignored ASN.1 field i.e., the following members must be either unexported
// or use the `asn1:"-"` struct tag.
type Extensible struct{}

// Tag constitutes an ASN.1 tag, consisting of its class and number. The class
// is indicated by the two most significant bits of the underlying integer. For
// details, see Section 8 of Rec. ITU-T X.680.
//
// Tag values can be constructed using bitwise operations:
//
//	TagMyType := asn1.ClassApplication | 15
//
// The default (zero) class is [asn1.ClassUniversal].
//
// Note that the encoding of the class and tag is different from the identifier
// bits in the BER encoding.
type Tag uint16

// Class holds the class part of an ASN.1 tag. The class acts as a namespace for
// the tag number. A Class value is an unsigned 2-bit integer. The relevant bits
// are the two most significant bits of the underlying integer. Class is an
// alias for Tag to make operations involving classes more convenient.
type Class = Tag

// classMask is the bitmask to extract the Class component from a Tag value.
const classMask = Tag(0b11 << 14)

// Predefined [Class] constants. These are all the possible values that can be
// encoded in the [Class] type.
const (
	ClassUniversal Class = iota << 14
	ClassApplication
	ClassContextSpecific
	ClassPrivate
)

// Class returns the class bits of t. The class bits are the two most
// significant bits of the return value.
func (t Tag) Class() Class {
	return t & classMask
}

// Number returns the tag number of t as an uint. The tag number does not
// include the class of the tag.
func (t Tag) Number() uint {
	return uint(t &^ classMask)
}

// String returns a string representation t in a format similar to the one used
// in ASN.1 notation. The tag number is enclosed by square brackets and prefixed
// with the class used. To avoid ambiguity, the UNIVERSAL word is used for
// universal tags, although this is not valid ASN.1 syntax.
func (t Tag) String() string {
	n := strconv.FormatUint(uint64(t.Number()), 10)
	switch t.Class() {
	case ClassUniversal:
		return "[UNIVERSAL " + n + "]"
	case ClassApplication:
		return "[APPLICATION " + n + "]"
	case ClassContextSpecific:
		return "[" + n + "]"
	case ClassPrivate:
		return "[PRIVATE " + n + "]"
	}
	panic("unreachable")
}

// TagReserved is the reserved tag number in the [ClassUniversal] namespace to
// be used by encoding rules. This assignment is defined in Rec. ITU-T X.680,
// Section 8, Table 1.
const TagReserved Tag = ClassUniversal | 0

// These are some ASN.1 tags defined in the [ClassUniversal] namespace. These
// assignments are defined in Rec. ITU-T X.680, Section 8, Table 1.
const (
	TagBoolean          = ClassUniversal | 1
	TagInteger          = ClassUniversal | 2
	TagBitString        = ClassUniversal | 3
	TagOctetString      = ClassUniversal | 4
	TagNull             = ClassUniversal | 5
	TagOID              = ClassUniversal | 6
	TagObjectDescriptor = ClassUniversal | 7
	TagExternal         = ClassUniversal | 8
	TagReal             = ClassUniversal | 9
	TagEnumerated       = ClassUniversal | 10
	TagEmbeddedPDV      = ClassUniversal | 11
	TagUTF8String       = ClassUniversal | 12
	TagRelativeOID      = ClassUniversal | 13
	TagTime             = ClassUniversal | 14
	TagSequence         = ClassUniversal | 16
	TagSet              = ClassUniversal | 17
	TagNumericString    = ClassUniversal | 18
	TagPrintableString  = ClassUniversal | 19
	TagTeletexString    = ClassUniversal | 20
	TagT61String        = TagTeletexString
	TagVideotexString   = ClassUniversal | 21
	TagIA5String        = ClassUniversal | 22
	TagUTCTime          = ClassUniversal | 23
	TagGeneralizedTime  = ClassUniversal | 24
	TagGraphicString    = ClassUniversal | 25
	TagVisibleString    = ClassUniversal | 26
	TagISO646String     = TagVisibleString
	TagGeneralString    = ClassUniversal | 27
	TagUniversalString  = ClassUniversal | 28
	TagCharacterString  = ClassUniversal | 29
	TagBMPString        = ClassUniversal | 30
	TagDate             = ClassUniversal | 31
	TagTimeOfDay        = ClassUniversal | 32
	TagDateTime         = ClassUniversal | 33
	TagDuration         = ClassUniversal | 34
)
