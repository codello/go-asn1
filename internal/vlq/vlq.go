// Package vlq implements [Variable-length quantity] encoding as used in MIDI or
// BER. A VLQ is essentially a base-128 representation of an unsigned integer
// with the addition of the eighth bit to mark continuation of bytes. VLQ is
// identical to [LEB128] except in endianness.
//
// [Variable-length quantity]: https://en.wikipedia.org/wiki/Variable-length_quantity
// [LEB128]: https://en.wikipedia.org/wiki/LEB128
package vlq

import (
	"errors"
	"io"
	"math/bits"
	"unsafe"
)

var (
	errNotMinimal = errors.New("vlq is not minimally encoded")
	errOverflow   = errors.New("vlq too large for target type")
)

// Read parses an unsigned VLQ from r. The maximum allowed value is limited by
// the size of T.
//
// Read will only read bytes belonging to the encoded VLQ. If r returns io.EOF
// on the first read, the returned error will be io.EOF as well.
//
// Read ignores an arbitrary amount of leading zeros (encoded as 0x80 bytes).
// Use [ReadMinimal] to parse a minimally-encoded VLQ.
func Read[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](r io.ByteReader) (T, error) {
	return read[T](r, false)
}

// ReadMinimal works like [Read] but returns an error if the VLQ is not
// minimally encoded (i.e. if it starts with a 0x80 byte).
func ReadMinimal[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](r io.ByteReader) (T, error) {
	return read[T](r, true)
}

// read implements [Read] and [ReadMinimal]. If minimal is true, the encoded VLQ
// must be minimally encoded.
func read[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](r io.ByteReader, minimal bool) (ret T, err error) {
	b, err := r.ReadByte()
	if err != nil {
		// io.EOF stays io.EOF
		return 0, err
	}
	if b == 0x80 && minimal {
		return 0, errNotMinimal
	}

	ret = T(b & 0x7f)
	numBits := bits.Len8(b & 0x7f)

	for b&0x80 != 0 {
		if b, err = r.ReadByte(); err != nil {
			break
		}
		ret <<= 7
		ret |= T(b & 0x7f)

		if numBits == 0 {
			numBits = bits.Len8(b & 0x7f)
		} else {
			numBits += 7
		}
		if numBits > int(unsafe.Sizeof(ret)*8) {
			return 0, errOverflow
		}
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return ret, err
}

// Length returns the number of bytes needed to encode n as a VLQ.
func Length[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](n T) int {
	if n == 0 {
		return 1
	}
	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}
	return l
}

// Write encodes i as a VLQ into w. Any error returned by w is returned by this
// function.
func Write[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](w io.ByteWriter, i T) (n int, err error) {
	l := Length(i)

	j := l - 1
	for ; j >= 0 && err == nil; j-- {
		b := byte(i>>(j*7)) & 0x7f
		if j > 0 {
			b |= 0x80
		}
		err = w.WriteByte(b)
	}

	return l - 1 - j, err
}
