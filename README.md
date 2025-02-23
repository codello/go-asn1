# ASN.1 Data Structures in Go

![Test Status](https://github.com/codello/go-asn1/actions/workflows/test.yml/badge.svg)

This package provides base types for implementing ASN.1 data structures as defined to [Rec. ITU-T X.680] in Go.
The goal of this package is not to provide a comprehensive implementation of all ASN.1 features
but to provide a framework for modeling, encoding, and decoding ASN.1 data structures in Go.
Encoding rules for data structures are implemented in the sub-packages of this module.

[Rec. ITU-T X.680]: https://www.itu.int/rec/T-REC-X.680

## Modeling of ASN.1 Data Structures

The `codello.dev/asn1` package defines rules for modeling ASN.1 data structures in Go.
The details are described in the package documentation.
The modeling approach takes inspiration from the `encoding` packages in the Go standard library
by using standard Go types such as `struct`s as base building blocks.

Consider the following data structure:

```asn1
DEFINITIONS
IMPLICIT TAGS
BEGIN

MyType ::= SEQUENCE {
    Num                  INTEGER
    Str                  UTF8String   OPTIONAL
    Data [APPLICATION 5] OCTET STRING
    ...
}
END
```

This could be translated into the following Go type:

```go
package main

import "codello.dev/asn1"

type MyType struct {
	Num  int
	Str  string `asn1:"optional"`
	Data []byte `asn1:"application,tag:5"`
	asn1.Extensible
}
```

Most of the standard Go types such as `string`, `int`, `float64`, or `time.Time` have defined counterparts in the package.
Custom types can also be used, although you probably need to implement support for the encoding rules you need to support.

## Encoding and Decoding of ASN.1 Data Structures

Encoding rules for ASN.1 data structures are implemented in the corresponding sub-packages.
Currently, the following encoding rules are supported:

- [x] Basic Encoding Rules (BER) as defined in [Rec. ITU-T X.690].
- [ ] Canonical Encoding Rules (CER) as defined in [Rec. ITU-T X.690].
- [ ] Distinguished Encoding Rules (DER) as defined in [Rec. ITU-T X.690].
- [ ] Packed Encoding Rules (PER) as defined in [Rec. ITU-T X.691].
- [ ] XML Encoding Rules (XER) as defined in [Rec. ITU-T X.693].
- [ ] Octet Encoding Rules (OER) as defined in [Rec. ITU-T X.696].
- [ ] JSON Encoding Rules (JER, or JSON/ER) as defined in [Rec. ITU-T X.697].

[Rec. ITU-T X.690]: https://www.itu.int/rec/T-REC-X.690
[Rec. ITU-T X.691]: https://www.itu.int/rec/T-REC-X.691
[Rec. ITU-T X.693]: https://www.itu.int/rec/T-REC-X.693
[Rec. ITU-T X.696]: https://www.itu.int/rec/T-REC-X.696
[Rec. ITU-T X.697]: https://www.itu.int/rec/T-REC-X.697

Encoding and decoding generally uses the `reflect` package and works similar to `encoding` packages in the standard library.
Currently only the Basic Encoding Rules are implemented.
You can encode or decode an ASN.1 type like this:

```go
package main

import (
	"io"

	"codello.dev/asn1/ber"
)

var val *MyType // see example above

func main() {
	var data []byte // decode from a byte slice
	err := ber.Unmarshal(data, &val)

	var r io.Reader // decode from an io.Reader
	err = ber.NewDecoder(r).Decode(&val)

	// encode to a byte slice
	data, err = ber.Marshal(val)

	// encode into an io.Writer
	var w io.Writer
	err = ber.NewEncoder(w).Encode(val)
}
```

If you have a need to implement a custom encoding scheme for a type, you can implement the interfaces `ber.BerEncoder`, `ber.BerDecoder`, and `ber.BerMatcher`.
For example if you wanted a custom struct type `MyString` to encode as if it were a string, you could do this as follows:

<details>
<summary>Example Implementation</summary>

```go
package main

import (
	"io"
	"strings"

	"codello.dev/asn1"
	"codello.dev/asn1/ber"
)

type MyString struct {
	data string
	// other fields
}

// BerEncode defines how s is encoded using BER. It returns identification
// information of the element (its ber.Header) as well as an io.WriterTo.
// The io.WriterTo value will do the actual encoding of the value into bytes.
func (s *MyString) BerEncode() (ber.Header, io.WriterTo, error) {
	return ber.Header{
		Tag:    asn1.Tag{Class: asn1.ClassApplication, Number: 15},
		Length: len(s.data),
	}, strings.NewReader(s.data), nil
}

// BerMatch is used to implement ASN.1 OPTIONAL elements. It is called before
// BerDecode to find out, if an element with the specified tag could be decoded
// by s. If BerMatch is not implemented, a value matches any tag.
func (s *MyString) BerMatch(tag asn1.Tag) bool {
	return tag == asn1.Tag{Class: asn1.ClassApplication, Number: 15}
}

// BerDecode decodes a data stream from r into s. The ber.ElementReader type
// provides various methods to simplify reading primitive or constructed
// types. For constructed types a common strategy is to wrap it in a
// ber.Decoder to do recursive decoding.
func (s *MyString) BerDecode(_ asn1.Tag, r ber.ElementReader) error {
	// you
	buf := strings.Builder{}
	_, err := io.Copy(&buf, r)
	s.data = buf.String()
	return err
}
```
</details>

## Contributing

If you encounter a bug or are missing a feature, please do open an issue.

Pull requests are also very welcome, for example to add support for additional encoding rules or ASN.1 features.
