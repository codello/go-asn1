// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ber

import (
	"bytes"
	"errors"
	"io"
	"iter"
	"unsafe"

	"codello.dev/asn1"
)

// StringReader implements reading of BER-encoded ASN.1 string types. String
// types can use the primitive or constructed encoding. When using the
// constructed encoding strings can be arbitrarily nested. StringReader
// understands both types of encodings and offers a flexible interface to read
// arbitrary string types.
//
// A StringReader must be created via [NewStringReader].
type StringReader struct {
	t asn1.Tag
	r Reader

	curr     *StringReader
	currLeaf Reader
}

// NewStringReader creates a new [StringReader] reading from r. r can be
// constructed or primitive. If r is using the constructed encoding, every
// subsequent data value must use the class and tag identified by the specified
// tag.
func NewStringReader(tag asn1.Tag, r Reader) *StringReader {
	return &StringReader{t: tag, r: r}
}

// Constructed indicates whether r is using the constructed or primitive
// encoding.
func (r *StringReader) Constructed() bool {
	return r.r.Constructed()
}

// next returns the next data value encoding in r that uses the primitive
// encoding. The returned reader may be empty. If no more data values follow,
// io.EOF is returned.
func (r *StringReader) next() (er Reader, err error) {
	if !r.Constructed() {
		if r.curr == nil {
			r.curr = r
			r.currLeaf = r.r
			return r.currLeaf, nil
		} else {
			r.currLeaf = nil
			return nil, io.EOF
		}
	}
	var h Header
	r.currLeaf = nil
	for r.currLeaf == nil {
		if r.curr == nil {
			h, er, err = r.r.Next()
			if err != nil {
				// err may be io.EOF
				return er, err
			}
			if h.Tag != r.t {
				return er, &SyntaxError{r.t, errors.New("non-matching encoding " + h.Tag.String() + " in constructed string")}
			}
			if !er.Constructed() {
				r.currLeaf = er
				break
			}
			r.curr = NewStringReader(h.Tag, er)
		}
		r.currLeaf, err = r.curr.next()
		if err == io.EOF {
			r.curr = nil
			continue
		} else if err != nil {
			r.curr = nil
			r.currLeaf = nil
			return nil, err
		}
		if h.Tag != r.t {
			return er, &SyntaxError{r.t, errors.New("non-matching encoding " + h.Tag.String() + " in constructed string")}
		}
	}
	return r.currLeaf, nil
}

// Strings returns a sequence of Reader values for data value encodings that all
// use the primitive encoding. There will be nor further items after an item
// where the error is non-nil. The sequence ends when io.EOF is encountered.
// Note that there will be no sequence item with an io.EOF error.
//
// If reading has already begun via Read or ReadByte, the sequence will only
// contain data value encodings that are completely unread. Any primitive
// encoding that has been partially read is discarded.
func (r *StringReader) Strings() iter.Seq2[Reader, error] {
	return func(yield func(Reader, error) bool) {
		er, err := r.next()
		for err == nil {
			if !yield(er, nil) {
				return
			}
			er, err = r.next()
		}
		if err != io.EOF {
			yield(nil, err)
		}
	}
}

// Read reads the encoded string as a sequence of bytes. This method takes care
// of combining strings that use the constructed encoding. After the whole
// string has been read, io.EOF is returned.
func (r *StringReader) Read(p []byte) (n int, err error) {
	var n0 int
	// read as many bytes as possible
	for n < len(p) && err == nil {
		if r.currLeaf == nil {
			// r.Next() sets r.currLeaf
			_, err = r.next()
			continue
		}
		n0, err = r.currLeaf.Read(p[n:])
		if err == io.EOF {
			r.currLeaf = nil
			err = nil
		}
		n += n0
	}
	return n, err
}

// ReadByte complements Read by only reading a single byte form r.
func (r *StringReader) ReadByte() (b byte, err error) {
	for err == nil {
		if r.currLeaf == nil {
			// r.Next() sets r.currLeaf
			_, err = r.next()
			continue
		}
		b, err = r.currLeaf.ReadByte()
		if err == io.EOF {
			r.currLeaf = nil
			err = nil
		}
	}
	return b, err
}

// Bytes returns all unread bytes from r in a new byte slice. The returned slice
// may be retained by the caller. If a read error occurs, it is returned.
func (r *StringReader) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	if r.r.Len() != LengthIndefinite {
		buf.Grow(r.r.Len())
	}
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}

// String returns all unread bytes from r as a string.
func (r *StringReader) String() (string, error) {
	buf, err := r.Bytes()
	return unsafe.String(unsafe.SliceData(buf), len(buf)), err
}
