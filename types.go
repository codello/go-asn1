// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn1

import (
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"
)

//region [UNIVERSAL 1] BOOLEAN
// Implemented as Go bool type.
//endregion

//region [UNIVERSAL 2] INTEGER
// Implemented as Go integer types and *big.Int.
//endregion

//region [UNIVERSAL 3] BIT STRING

// BitString implements the ASN.1 BIT STRING type. A bit string is padded up to
// the nearest byte in memory and the number of valid bits is recorded. Padding
// bits will be encoded and decoded as zero bits.
//
// See also section 22 of Rec. ITU-T X.680.
type BitString struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

// IsValid reports whether there are enough bytes in s for the indicated
// BitLength.
func (s BitString) IsValid() bool {
	return len(s.Bytes) >= (s.BitLength+8-1)/8
}

// Len returns the number of bits in s.
func (s BitString) Len() int {
	return s.BitLength
}

// At returns the bit at the given index. If the index is out of range At panics.
func (s BitString) At(i int) int {
	if i < 0 || i >= s.BitLength {
		panic("index out of range")
	}
	x := i / 8
	y := 7 - uint(i%8)
	return int(s.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (s BitString) RightAlign() []byte {
	shift := uint(8 - (s.BitLength % 8))
	if shift == 8 || len(s.Bytes) == 0 {
		return s.Bytes
	}

	a := make([]byte, len(s.Bytes))
	a[0] = s.Bytes[0] >> shift
	for i := 1; i < len(s.Bytes); i++ {
		a[i] = s.Bytes[i-1] << (8 - shift)
		a[i] |= s.Bytes[i] >> shift
	}

	return a
}

// String formats s into a readable binary representation. Bits will be grouped
// into bytes. The last group may have fewer than 8 characters.
func (s BitString) String() string {
	if len(s.Bytes) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(s.BitLength)
	for _, b := range s.Bytes[:len(s.Bytes)-1] {
		sb.WriteString(strconv.FormatUint(uint64(b), 2))
		sb.WriteByte(' ')
	}
	sb.WriteString(strconv.FormatUint(uint64(s.Bytes[len(s.Bytes)-1]>>s.BitLength), 2))
	return sb.String()
}

//endregion

//region [UNIVERSAL 4] OCTET STRING
// Implemented as Go byte slice, byte array and
// encoding.BinaryUnmarshaler/encoding.BinaryMarshaler.
//endregion

//region [UNIVERSAL 5] NULL

// Null represents the ASN.1 NULL type. If your data structure contains fixed
// NULL elements this type offers a convenient way to indicate their presence.
// If your data structure contains fields that may or may not be null, it is
// probably better to use a nullable type such as a pointer.
//
// See also section 24 of Rec. ITU-T X.680.
type Null struct{}

//endregion

//region [UNIVERSAL 6] OBJECT IDENTIFIER

// An ObjectIdentifier represents an ASN.1 OBJECT IDENTIFIER. The semantics of an object identifier are specified in [Rec. ITU-T X.660].
//
// See also section 32 of Rec. ITU-T X.680.
//
// [Rec. ITU-T X.660]: https://www.itu.int/rec/T-REC-X.660
type ObjectIdentifier []uint

// Equal reports whether oid and other represent the same identifier.
func (oid ObjectIdentifier) Equal(other ObjectIdentifier) bool {
	return slices.Equal(oid, other)
}

// String returns the dot-separated notation of oid.
func (oid ObjectIdentifier) String() string {
	var s strings.Builder
	s.Grow(32)

	buf := make([]byte, 0, 19)
	for i, v := range oid {
		if i > 0 {
			s.WriteByte('.')
		}
		s.Write(strconv.AppendInt(buf, int64(v), 10))
	}

	return s.String()
}

//endregion

//region [UNIVERSAL 7] ObjectDescriptor
// Currently not implemented. The underlying type of ObjectDescriptor is
// GraphicString which can escape into non-ASCII character sets.
//endregion

//region [UNIVERSAL 8] EXTERNAL
// The EXTERNAL type is currently not implemented.
//endregion

//region [UNIVERSAL 09] REAL
// Implemented as Go float32 and float64 types and *big.Float.
//endregion

//region [UNIVERSAL 10] ENUMERATED

// Enumerated exists as a type mainly for documentation purposes. Any type with
// an underlying integer type is recognized as the ENUMERATED type. Types may
// implement an IsValid() bool method to indicate whether a value is valid for
// the enum.
//
// See also section 20 of Rec. ITU-T X.680.
type Enumerated int

//endregion

//region [UNIVERSAL 11] EMBEDDED PDV
// This type is currently not implemented.
//endregion

//region [UNIVERSAL 12] UTF8String

// UTF8String represents the ASN.1 UTF8String type. It can only hold valid UTF-8
// values. UTF8String is also the default type for standard Go strings.
//
// See also section 41 of Rec. ITU-T X.680.
type UTF8String string

// IsValid reports whether s is a valid UTF-8 string.
func (s UTF8String) IsValid() bool {
	return utf8.ValidString(string(s))
}

//endregion

//region [UNIVERSAL 13] RELATIVE-OID

// RelativeOID represents the ASN.1 RELATIVE OID type. This is similar to the
// [ObjectIdentifier] type, but a RelativeOID is only a suffix of an OID.
//
// See also section 32 of Rec. ITU-T X.680.
type RelativeOID []uint

// Equal reports whether oid and other represent the same identifier.
func (oid RelativeOID) Equal(other RelativeOID) bool {
	return slices.Equal(oid, other)
}

// String returns the dot-separated notation of oid.
func (oid RelativeOID) String() string {
	var s strings.Builder
	s.Grow(32)

	buf := make([]byte, 0, 19)
	for i, v := range oid {
		if i > 0 {
			s.WriteByte('.')
		}
		s.Write(strconv.AppendInt(buf, int64(v), 10))
	}

	return s.String()
}

//endregion

//region [UNIVERSAL 14] TIME

// Time represents the ASN.1 TIME type. This type can only hold a subset of
// valid ASN.1 TIME values, namely those that can be represented by a time
// instant. In particular recurrences or intervals are not supported.
//
// See also section 38 of Rec. ITU-T X.680.
type Time time.Time

// String returns an ISO 8601 compatible representation of t.
func (t Time) String() string {
	tt := time.Time(t)
	b := strings.Builder{}
	b.Grow(34) // allocate enough space for nanosecond precision
	b.WriteString(itoaN(tt.Year(), 4))
	b.WriteByte('-')
	b.WriteString(itoaN(tt.Month(), 2))
	b.WriteByte('-')
	b.WriteString(itoaN(tt.Day(), 2))
	b.WriteByte('T')
	b.WriteString(itoaN(tt.Hour(), 2))
	b.WriteByte(':')
	b.WriteString(itoaN(tt.Minute(), 2))
	b.WriteByte(':')
	b.WriteString(itoaN(tt.Second(), 2))
	if tt.Nanosecond() > 0 {
		s := strconv.FormatFloat(float64(tt.Nanosecond())/float64(time.Second), 'f', -1, 64)
		b.WriteString(s[1:])
	}
	if tt.Location() == time.Local {
		return b.String()
	}
	_, offset := tt.Zone()
	offset /= 60
	if offset == 0 {
		b.WriteByte('Z')
		return b.String()
	}
	if offset < 0 {
		b.WriteByte('-')
	} else {
		b.WriteByte('+')
	}
	b.WriteString(itoaN(offset/60, 2))
	b.WriteByte(':')
	b.WriteString(itoaN(offset%60, 2))
	return b.String()
}

//endregion

//region [UNIVERSAL 16] SEQUENCE
// The SEQUENCE type is implemented by custom struct types and slices/arrays.
//endregion

//region [UNIVERSAL 17] SET

// Set represents the ASN.1 SET OF type. This is only a very basic
// implementation of a set in Go. If you have specific requirements working with
// sets you might be better off to define your own set type.
//
// See also section 27 and 28 of Rec. ITU-T X.680.
type Set[T comparable] map[T]struct{}

// NewSet creates a new set with the specified elements.
func NewSet[T comparable](ts ...T) Set[T] {
	s := make(Set[T], len(ts))
	for _, v := range ts {
		s[v] = struct{}{}
	}
	return s
}

// Add adds value to the set.
func (s Set[T]) Add(value T) {
	s[value] = struct{}{}
}

// Remove removes value from the set, if it was present.
func (s Set[T]) Remove(value T) {
	delete(s, value)
}

// Contains indicates whether value is contained within the set.
func (s Set[T]) Contains(value T) bool {
	_, ok := s[value]
	return ok
}

//endregion

//region [UNIVERSAL 18] NumericString

// NumericString corresponds to the ASN.1 NumericString type. A NumericString
// can only consist of the digits 0-9 and space. Note that it is possible to
// create NumericString values in Go that violate this constraint. Use the
// IsValid method to check whether a string's contents are numeric.
//
// See also section 41 of Rec. ITU-T X.680.
type NumericString string

// IsValid reports whether s consists only of allowed numeric characters.
func (s NumericString) IsValid() bool {
	for i := 0; i < len(s); i++ {
		if !isNumeric(s[i]) {
			return false
		}
	}
	return true
}

// isNumeric reports whether b can appear in an ASN.1 NumericString.
func isNumeric(b byte) bool {
	return '0' <= b && b <= '9' || b == ' '
}

//endregion

//region [UNIVERSAL 19] PrintableString

// PrintableString represents the ASN.1 type PrintableString. A printable string
// can only contain the following ASCII characters:
//
//	A-Z	// upper case letters
//	a-z	// lower case letters
//	0-9	// digits
//	 	// space
//	'	// apostrophe
//	()	// Parenthesis
//	+-/	// plus, hyphen, solidus
//	.,:	// fill stop, comma, colon
//	=	// equals sign
//	?	// question mark
//
// See also section 41 of Rec. ITU-T X.680.
type PrintableString string

// IsValid reports whether s consists only of printable characters.
func (s PrintableString) IsValid() bool {
	for i := 0; i < len(s); i++ {
		if !isPrintable(s[i], false, false) {
			return false
		}
	}
	return true
}

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// If asterisk is allowAsterisk then '*' is also allowed, reflecting existing
// practice. If ampersand is allowAmpersand then '&' is allowed as well.
func isPrintable(b byte, asterisk, ampersand bool) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
		// This is technically not allowed in a PrintableString.
		// However, x509 certificates with wildcard strings don't
		// always use the correct string type so we permit it.
		(ampersand && b == '*') ||
		// This is not technically allowed either. However, not
		// only is it relatively common, but there are also a
		// handful of CA certificates that contain it. At least
		// one of which will not expire until 2027.
		(asterisk && b == '&')
}

//endregion

//region [UNIVERSAL 20] TeletexString (T61String)
// This type is currently not implemented. Correcly decoding a TeletexString is
// probably outside the scope of this package.
//endregion

//region [UNIVERSAL 21] VideotexString
// This type is currently not implemented. Correcly decoding a VideotexString is
// probably outside the scope of this package.
//endregion

//region [UNIVERSAL 22] IA5String

// IA5String represents the ASN.1 type IA5String. An IA5String must consist on
// ASCII characters only. Note that it is possible to create IA5String values in
// Go that violate this constraint. Use the IsValid method to check whether a
// string's contents are ASCII only.
//
// See also section 41 of Rec. ITU-T X.680.
type IA5String string

// IsValid reports whether the contents of s consist only of ASCII characters.
func (s IA5String) IsValid() bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

//endregion

//region [UNIVERSAL 23] UTCTime

// UTCTime represents the corresponding ASN.1 type. Only dates between
// 1950 and 2049 can be represented by this type.
//
// See also section 47 of Rec. ITU-T X.680.
type UTCTime time.Time

// IsValid reports whether the year of t is between 1950 and 2049.
func (t UTCTime) IsValid() bool {
	year := time.Time(t).Year()
	return year >= 1950 && year < 2050
}

// String returns the time of t in the format YYMMDDhhmmssZ or YYMMDDhhmmss+hhmm.
func (t UTCTime) String() string {
	tt := time.Time(t)
	b := strings.Builder{}
	b.Grow(17)
	b.WriteString(itoaN(tt.Year()%100, 2))
	b.WriteString(itoaN(tt.Month(), 2))
	b.WriteString(itoaN(tt.Day(), 2))
	b.WriteString(itoaN(tt.Hour(), 2))
	b.WriteString(itoaN(tt.Minute(), 2))
	b.WriteString(itoaN(tt.Second(), 2))
	_, offset := tt.Zone()
	offset /= 60
	if offset == 0 {
		b.WriteByte('Z')
		return b.String()
	}
	if offset < 0 {
		b.WriteByte('-')
	} else {
		b.WriteByte('+')
	}
	b.WriteString(itoaN(offset/60, 2))
	b.WriteString(itoaN(offset%60, 2))
	return b.String()
}

// itoaN returns the base 10 string representation of the absolute value of i,
// truncated or zero padded to exactly n digits.
func itoaN[T ~int](i T, n int) string {
	if i < 0 {
		i = -i
	}
	bs := make([]byte, n)
	for ; n > 0; n-- {
		bs[n-1] = '0' + byte(i%10)
		i /= 10
	}
	return unsafe.String(unsafe.SliceData(bs), len(bs))
}

//endregion

//region [UNIVERSAL 24] GeneralizedTime

// GeneralizedTime represents the corresponding ASN.1 type. This type can
// represent dates between years 1 and 9999.
//
// See also section 46 of Rec. ITU-T X.680.
type GeneralizedTime time.Time

// IsValid reports if the year of t is between 1 and 9999.
func (t GeneralizedTime) IsValid() bool {
	year := time.Time(t).Year()
	return year >= 1 && year <= 9999
}

// String returns a string representation of t that matches its representation
// in ASN.1 notation.
func (t GeneralizedTime) String() string {
	tt := time.Time(t)
	b := strings.Builder{}
	b.Grow(29) // allocate enough space for nanosecond precision
	b.WriteString(itoaN(tt.Year()%10000, 4))
	b.WriteString(itoaN(tt.Month(), 2))
	b.WriteString(itoaN(tt.Day(), 2))
	b.WriteString(itoaN(tt.Hour(), 2))
	b.WriteString(itoaN(tt.Minute(), 2))
	b.WriteString(itoaN(tt.Second(), 2))
	if tt.Nanosecond() > 0 {
		s := strconv.FormatFloat(float64(tt.Nanosecond())/float64(time.Second), 'f', -1, 64)
		b.WriteString(s[1:])
	}
	if tt.Location() == time.Local {
		return b.String()
	}
	_, offset := tt.Zone()
	offset /= 60
	if offset == 0 {
		b.WriteByte('Z')
		return b.String()
	}
	if offset < 0 {
		b.WriteByte('-')
	} else {
		b.WriteByte('+')
	}
	b.WriteString(itoaN(offset/60, 2))
	b.WriteString(itoaN(offset%60, 2))
	return b.String()
}

//endregion

//region [UNIVERSAL 25] GraphicString
// This type is currently not implemented. Correctly decoding a GraphicString is
// probably outside the scope of this package.
//endregion

//region [UNIVERSAL 26] VisibleString

// VisibleString represents the corresponding ASN.1 type. It is limited to
// visible ASCII characters. In particular this does not include ASCII control
// characters. Note that it is possible to create VisibleString values in
// Go that violate this constraint. Use the IsValid method to check whether a
// string's contents are visible ASCII only.
//
// See also section 41 of Rec. ITU-T X.680.
type VisibleString string

// IsValid reports whether s only consists of visible ASCII characters.
func (s VisibleString) IsValid() bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] >= 0x7F {
			return false
		}
	}
	return true
}

//endregion

//region [UNIVERSAL 27] GeneralString
// This type is currently not implemented. Correctly decoding a GeneralString is
// probably outside the scope of this package.
//endregion

//region [UNIVERSAL 28] UniversalString

// UniversalString represents the corresponding ASN.1 type. A UniversalString
// can contain any Unicode character. Note that the Go type uses standard Go
// strings which are UTF-8 encoded. The encoding of a UniversalString in BER for
// example uses big endian UTF-32.
//
// In most cases [UTF8String] is a more appropriate type.
//
// See also section 41 of Rec. ITU-T X.680.
type UniversalString string

// IsValid reports whether consists of a valid UTF-8 encoding. Note that this
// does not validate the encoding of a UniversalString but its Go
// representation.
func (s UniversalString) IsValid() bool {
	return utf8.ValidString(string(s))
}

//endregion

//region [UNIVERSAL 29] CHARACTER STRING
// The CHARACTER STRING type is not currently supported.
//endregion

//region [UNIVERSAL 30] BMPString

// BMPString represents the corresponding ASN.1 type. A BMPString can hold any
// character of the Unicode Basic Multilingual Plane. Note that this type uses
// standard Go strings which are UTF-8 encoded. The encoding of a BMPString in
// BER for example uses big endian UTF-16.
//
// In most cases [UTF8String] is a more appropriate type.
//
// See also section 41 of Rec. ITU-T X.680.
type BMPString string

// IsValid reports whether s contains valid UTF-8.
func (s BMPString) IsValid() bool {
	for _, r := range s {
		if r > 0xFFFF || (r >= 0x8000 && r < 0xE000) {
			return false
		}
	}
	return true
}

//endregion

//region [UNIVERSAL 31] DATE

// Date represents the ASN.1 DATE type. The value must not contain time or
// location information.
//
// See also section 38 of Rec. ITU-T X.680.
type Date time.Time

// IsValid reports whether t only contains date information.
func (t Date) IsValid() bool {
	tt := time.Time(t)
	return tt.Hour() == 0 && tt.Minute() == 0 && tt.Second() == 0 && tt.Nanosecond() == 0 && tt.Location() == time.Local
}

func (d Date) String() string {
	tt := time.Time(d)
	b := strings.Builder{}
	b.Grow(10)
	b.WriteString(itoaN(tt.Year()%10000, 4))
	b.WriteByte('-')
	b.WriteString(itoaN(tt.Month(), 2))
	b.WriteByte('-')
	b.WriteString(itoaN(tt.Day(), 2))
	return b.String()
}

//endregion

//region [UNIVERSAL 32] TIME-OF-DAY

// TimeOfDay represents the ASN.1 TIME-OF-DAY type. The value must not contain
// date or location information.
//
// See also section 38 of Rec. ITU-T X.680.
type TimeOfDay time.Time

// IsValid reports whether t only contains time data.
func (t TimeOfDay) IsValid() bool {
	tt := time.Time(t)
	return tt.Year() == 1 && tt.Month() == 1 && tt.Day() == 1 && tt.Location() == time.Local
}

// String returns the ASN.1 notation of t.
func (t TimeOfDay) String() string {
	tt := time.Time(t)
	b := strings.Builder{}
	b.Grow(8)
	b.WriteString(itoaN(tt.Hour(), 2))
	b.WriteByte(':')
	b.WriteString(itoaN(tt.Minute(), 2))
	b.WriteByte(':')
	b.WriteString(itoaN(tt.Second(), 2))
	return b.String()
}

//endregion

//region [UNIVERSAL 33] DATE-TIME

// DateTime represents the ASN.1 DATE-TIME type. Values cannot contain location
// information.
//
// See also section 38 of Rec. ITU-T X.680.
type DateTime time.Time

// IsValid reports whether t contains only date and time information.
func (t DateTime) IsValid() bool {
	tt := time.Time(t)
	return tt.Location() == time.Local
}

// String returns the ASN.1 notation of d.
func (t DateTime) String() string {
	tt := time.Time(t)
	b := strings.Builder{}
	b.Grow(19)
	b.WriteString(itoaN(tt.Year()%10000, 4))
	b.WriteByte('-')
	b.WriteString(itoaN(tt.Month(), 2))
	b.WriteByte('-')
	b.WriteString(itoaN(tt.Day(), 2))
	b.WriteByte('T')
	b.WriteString(itoaN(tt.Hour(), 2))
	b.WriteByte(':')
	b.WriteString(itoaN(tt.Minute(), 2))
	b.WriteByte(':')
	b.WriteString(itoaN(tt.Second(), 2))
	return b.String()
}

//endregion

//region [UNIVERSAL 34] DURATION

// Duration represents the ASN.1 DURATION type. Only durations that can be
// represented as a [time.Duration] are valid, that is durations cannot use
// units above hours.
//
// See also section 38 of Rec. ITU-T X.680.
type Duration time.Duration

// String returns the ASN.1 notation of d.
func (d Duration) String() string {
	b := strings.Builder{}
	dd := time.Duration(d)
	if dd == 0 {
		return "PT0S"
	} else if dd < 0 {
		b.WriteString("-PT")
		dd = -dd
	} else {
		b.WriteString("PT")
	}
	h := int64(dd.Hours())
	if h != 0 {
		b.WriteString(strconv.FormatInt(h, 10))
		b.WriteByte('H')
		dd -= time.Duration(h) * time.Hour
	}
	b.Grow(16)
	m := int64(dd.Minutes())
	if m != 0 {
		b.WriteString(strconv.FormatInt(m, 10))
		b.WriteByte('M')
		dd -= time.Duration(m) * time.Minute
	}
	s := int64(dd.Seconds())
	if s != 0 {
		b.WriteString(strconv.FormatInt(s, 10))
		dd -= time.Duration(s) * time.Second
		if dd > 0 {
			s := strconv.FormatFloat(dd.Seconds(), 'f', -1, 64)
			b.WriteString(s[1:])
		}
		b.WriteByte('S')
	}
	return b.String()
}

//endregion
