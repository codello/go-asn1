// Package tlv implements streaming encoding and decoding of the
// tag-length-value (TLV) format used by the Basic Encoding Rules (BER) and
// related encoding rules as specified in [Rec. ITU-T X.690].
// See also “[A Layman's Guide to a Subset of ASN.1, BER, and DER]”.
//
// The [Encoder] and [Decoder] types are used to encode or decode a stream of
// TLV headers and their values. This package deals with the syntactic layer of
// TLV-encoding while other packages such as [codello.dev/asn1/ber] deal with
// the semantic layer of BER.
//
// # Headers and Values
//
// In BER each value is encoded using a tag-length-value format. The tag and
// length (we call them a header) are represented by the [Header] type. Values
// can use the primitive or constructed encoding. Primitive values are
// represented by the [Value] type (which is an [io.Reader]). Values using the
// constructed encoding are followed by more BER-encoded values and can either
// end implicitly (when using definite-length encoding) or explicitly
// (indefinite length).
//
// The end of a constructed element is signalled by a zero [Header] (or,
// equivalently, using [TagEndOfContents]). The [Encoder] and [Decoder] types
// expect and produce an end-of-contents marker at the end of every constructed
// encoding, regardless of whether it uses the definite or indefinite-length
// encoding.
//
// The [Encoder] and [Decoder] types contain methods to read and write BER
// values as a stream of headers, values, and end-of-content markers. They
// maintain an internal state to validate whether the sequence of TLVs forms a
// valid BER encoding.
//
// [Rec. ITU-T X.690]: https://www.itu.int/rec/T-REC-X.690
// [A Layman's Guide to a Subset of ASN.1, BER, and DER]: http://luca.ntop.org/Teaching/Appunti/asn1.html
package tlv

import (
	"math"
	"strconv"

	"codello.dev/asn1"
)

// TagEndOfContents is the tag that signifies the end of a constructed element.
// You can use this constant for clarity, the following are the same:
//
//	tlv.Header{}
//	tlv.Header{Tag: tlv.TagEndOfContents}
//	tlv.EndOfContents
const TagEndOfContents = asn1.TagReserved

// EndOfContents is the end-of-contents marker signalling the end of a
// constructed element. The following are equivalent:
//
//	tlv.Header{}
//	tlv.Header{Tag: tlv.TagEndOfContents}
//	tlv.EndOfContents
var EndOfContents = Header{Tag: TagEndOfContents}

// LengthIndefinite when used as a magic number for the length of a [Header]
// indicates that the data value is encoded using the constructed
// indefinite-length format.
const LengthIndefinite = -1

// CombinedLength returns the length of a data value encoding (not including its
// header) consisting of data value encodings of the specified lengths. If any
// of the passed lengths are [LengthIndefinite] or the result does not fit into
// the int type, the result is [LengthIndefinite].
func CombinedLength(ls ...int) int {
	sum := 0
	for _, l := range ls {
		if l == LengthIndefinite {
			return LengthIndefinite
		}
		if l > math.MaxInt-sum { // overflow
			return LengthIndefinite
		}
		sum += l
	}
	return sum
}

// MinLength returns the smaller of the two given lengths. This function is
// aware of potentially indefinite lengths and treats them properly.
func MinLength(l1, l2 int) int {
	// this works because the bit pattern of LengthIndefinite is 1111...1, which is
	// the larges uint. So any other value will be smaller.
	//
	// max(..., LengthIndefinite) fixes invalid negative lengths
	return max(int(min(uint(l1), uint(l2))), LengthIndefinite)
}

// Header represents a TLV header. The [Header.Length] may be [LengthIndefinite]
// if an indefinite-length encoding is used. It is invalid to use the
// indefinite-length encoding when [Header.Constructed] = false.
type Header struct {
	Tag         asn1.Tag
	Constructed bool
	Length      int
}

// String returns a string representation of h.
func (h Header) String() string {
	if h == (Header{}) {
		return "EndOfContents"
	}
	s := h.Tag.String()
	if h.Constructed {
		s += "/c"
	} else {
		s += "/p"
	}
	s += ":" + strconv.Itoa(h.Length)
	return s
}

// requireKeyedLiterals can be embedded in a struct to require keyed literals.
type requireKeyedLiterals struct{}

// nonComparable can be embedded in a struct to prevent comparability.
type nonComparable [0]func()
