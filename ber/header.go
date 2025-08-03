// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"errors"
	"io"
	"math"
	"math/bits"

	"codello.dev/asn1"
)

// LengthIndefinite when used as a magic number for the length of a [Header]
// indicates that the data value is encoded using the constructed
// indefinite-length format.
const LengthIndefinite = -1

// CombinedLength returns the length of a data value encoding (not including its
// header) consisting of data value encodings of the specified lengths. If any
// of the passed lengths are [LengthIndefinite], the result is
// [LengthIndefinite] as well.
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

// Header represents the BER header of an encoded data value. The Length of the
// Header indicates the number of bytes that make up the content octets of the
// encoded data value. Length can also be the special value [LengthIndefinite]
// if the encoding uses the constructed indefinite-length encoding. In that
// case, Constructed must also be set to true.
type Header struct {
	Tag         asn1.Tag
	Length      int
	Constructed bool
}

// numBytes computes the number of bytes required to BER-encode h. The encode
// method will write this exact number of bytes.
func (h Header) numBytes() int {
	l := 1 // class, constructed, tag
	if h.Tag.Number() >= 31 {
		// tag does not fit
		l += base128IntLength(h.Tag.Number())
	}
	l++ // length
	if h.Length == LengthIndefinite || h.Length < 128 {
		return l
	}
	// multi-byte length
	l++
	for hl := h.Length; hl > 255; hl >>= 8 {
		l++
	}
	return l
}

// writeTo writes the BER-encoding of h to w. It returns the number of bytes
// written as well as any error that occurs during writing.
func (h Header) writeTo(w io.ByteWriter) (n int64, err error) {
	b := uint8(h.Tag.Class() >> 8)
	if h.Constructed {
		b |= 0x20
	}
	if h.Tag.Number() < 31 {
		b |= uint8(h.Tag.Number())
		if err = w.WriteByte(b); err != nil {
			return n, err
		}
		n++
	} else {
		b |= 0x1f
		if err = w.WriteByte(b); err != nil {
			return n, err
		}
		n, err = writeBase128Int(w, h.Tag.Number())
		n++
		if err != nil {
			return n, err
		}
	}

	if h.Length == LengthIndefinite {
		err = w.WriteByte(0x80)
	} else if h.Length >= 128 {
		numBytes := 1
		l := h.Length
		for l > 255 {
			numBytes++
			l >>= 8
		}
		err = w.WriteByte(0x80 | byte(numBytes))
		for ; numBytes > 0 && err == nil; numBytes-- {
			n++
			err = w.WriteByte(byte(h.Length >> uint((numBytes-1)*8)))
		}
	} else {
		err = w.WriteByte(byte(h.Length))
	}
	if err == nil {
		n++
	}

	return n, err
}

// decodeHeader reads the identifier and length octets of a data value encoding
// from r and returns them as a [Header] value. If the encoding is invalid an
// error is returned.
//
// If r returns io.EOF on the first read, the returned error will be io.EOF as
// well. If r produces a valid BER-encoded header, this method will not read any
// bytes past the header.
func decodeHeader(r io.ByteReader) (h Header, err error) {
	b, err := r.ReadByte()
	if err != nil {
		return Header{}, err
	}
	h = Header{
		Tag:         asn1.Tag(b>>6)<<14 | asn1.Tag(b&0x1f),
		Constructed: b&0x20 == 0x20,
	}

	// If the bottom five bits are set, then the tag number is actually base 128
	// encoded afterward
	if b&0x1f == 0x1f {
		var n uint
		n, err = decodeBase128(r)
		// FIXME: Check overflow
		h.Tag = h.Tag.Class() | (asn1.Tag(n) &^ (0b11 << 14))
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return h, err
		}
	}

	if b, err = r.ReadByte(); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return h, err
	}
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		h.Length = int(b & 0x7f)
	} else if b == 0x80 {
		h.Length = LengthIndefinite
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		h.Length = 0
		for i := 0; i < numBytes; i++ {
			if b, err = r.ReadByte(); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return h, err
			}
			if h.Length >= 1<<23 {
				// We can't shift h.length up without overflowing.
				err = errors.New("length too large")
				continue
			}
			h.Length <<= 8
			h.Length |= int(b)
		}
	}
	return h, err
}

// decodeBase128 reads and parses a base-128 encoded uint from r. The maximum
// supported value is limited by the size of an uint.
//
// If r produces a valid base-128 integer, only the bytes belonging to the
// encoded value will be read from r. If r returns io.EOF on the first read, the
// returned error will be io.EOF as well.
func decodeBase128(r io.ByteReader) (uint, error) {
	b, err := r.ReadByte()
	if err != nil {
		// io.EOF stays io.EOF
		return 0, err
	}
	var syntaxError error
	if b == 0x80 {
		// integers should be minimally encoded, so the leading octet
		// should never be 0x80
		syntaxError = errors.New("base 128 integer is not minimally encoded")
	}
	ret := uint(b & 0x7f)
	numBits := bits.Len8(b & 0x7f)

	for b&0x80 != 0 {
		b, err = r.ReadByte()
		if err != nil {
			break
		}
		ret <<= 7
		ret |= uint(b & 0x7f)
		if numBits == 0 {
			numBits = bits.Len8(b & 0x7f)
		} else {
			numBits += 7
		}
		if numBits > bits.UintSize {
			syntaxError = errors.New("base 128 integer too large")
		}
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if syntaxError != nil {
		err = syntaxError
	}
	return ret, err
}

// base128IntLength returns the number of bytes needed to encode n as a base 128
// integer.
func base128IntLength(n uint) int {
	if n == 0 {
		return 1
	}
	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}
	return l
}

// writeBase128Int encodes i as a base 128 integer into w. Any error returned by
// w is returned by this function.
func writeBase128Int(w io.ByteWriter, i uint) (n int64, err error) {
	l := base128IntLength(i)

	j := l - 1
	for ; j >= 0 && err == nil; j-- {
		b := byte(i >> (j * 7))
		b &= 0x7f
		if j != 0 {
			b |= 0x80
		}
		err = w.WriteByte(b)
	}

	return int64(l - 1 - j), err
}
