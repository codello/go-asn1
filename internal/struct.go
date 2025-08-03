// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"iter"
	"math/bits"
	"reflect"
	"strconv"
	"strings"

	"codello.dev/asn1"
)

// FieldParameters is the parsed representation of tag string from a struct
// field.
type FieldParameters struct {
	Ignore   bool     // true iff this field should be ignored
	Tag      asn1.Tag // the EXPLICIT or IMPLICIT class and tag number (maybe nil).
	Optional bool     // true iff the field is OPTIONAL
	Explicit bool     // true iff an EXPLICIT tag is in use.
	OmitZero bool     // true iff this should be omitted if zero when marshaling.
	Nullable bool     // true iff this can encode to and decode from null.
}

// ParseFieldParameters will parse a given tag string into a FieldParameters
// structure, ignoring unknown parts of the string. The string must be formatted
// according to the package documentation of the asn1 package.
func ParseFieldParameters(str string) (ret FieldParameters) {
	hasClass := false
	for part := range strings.SplitSeq(str, ",") {
		switch {
		case part == "-":
			ret.Ignore = true
		case part == "optional":
			ret.Optional = true
		case part == "explicit":
			ret.Explicit = true
		case strings.HasPrefix(part, "tag:"):
			i, err := strconv.ParseUint(part[4:], 10, bits.UintSize)
			if err == nil {
				if !hasClass {
					ret.Tag = asn1.ClassContextSpecific
				}
				// TODO: Check overflow?
				ret.Tag = ret.Tag.Class() | asn1.Tag(i)
			}
		case part == "application":
			ret.Tag = ret.Tag&^(0b11<<14) | asn1.ClassApplication
			hasClass = true
		case part == "private":
			ret.Tag = ret.Tag&^(0b11<<14) | asn1.ClassPrivate
			hasClass = true
		case part == "universal":
			ret.Tag = ret.Tag&^(0b11<<14) | asn1.ClassUniversal
			hasClass = true
		case part == "omitzero":
			ret.OmitZero = true
		case part == "nullable":
			ret.Nullable = true
		}
	}
	return ret
}

// ExtensibleType is the type of asn1.Extensible.
var ExtensibleType = reflect.TypeFor[asn1.Extensible]()

// StructFields returns a sequence that iterates over the fields of the struct
// identified by v. Struct fields with a `asn1:"-"` tag are ignored, as are
// non-exported struct fields. Fields of embedded structs returned as if they
// were fields of the containing struct, except for fields of type
// asn1.Extensible.
func StructFields(v reflect.Value) iter.Seq2[reflect.Value, FieldParameters] {
	return func(yield func(reflect.Value, FieldParameters) bool) {
		t := v.Type()
		for i := range t.NumField() {
			field := t.Field(i)
			params := ParseFieldParameters(field.Tag.Get("asn1"))
			if params.Ignore || !field.IsExported() {
				continue
			}
			if field.Anonymous && params.Tag == 0 && field.Type.Kind() == reflect.Struct && field.Type != ExtensibleType {
				for vv, params := range StructFields(v.Field(i)) {
					if !yield(vv, params) {
						return
					}
				}
				continue
			}
			if !yield(v.Field(i), params) {
				return
			}
		}
	}
}
