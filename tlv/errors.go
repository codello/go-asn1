package tlv

import (
	"errors"
	"io"
	"strconv"
)

var (
	errUnexpectedEOC = errors.New("unexpected end of contents")
	errInvalidEOC    = errors.New("invalid end of contents")
	errTruncated     = errors.New("truncated data value")
	errClosed        = errors.New("tlv: value closed")
)

// ioError represents an error that occurred when reading from or writing to an
// underlying data stream.
type ioError struct {
	action string // either "read" or "write"
	err    error
}

func (e *ioError) Unwrap() error { return e.err }
func (e *ioError) Error() string { return e.action + " error: " + e.err.Error() }

// SyntaxError represents an error in the TLV encoding. The error value contains
// the location of the error within the input as well as the [Header] of the
// surrounding data value.
type SyntaxError struct {
	requireKeyedLiterals
	nonComparable

	Err error // underlying error

	// ByteOffset is the location of the error. The location is usually the start of
	// the TLV header containing the error.
	ByteOffset int64

	// Header is the TLV header of the constructed TLV whose value contained the
	// malformed data.
	Header Header
}

func (e *SyntaxError) Unwrap() error { return e.Err }
func (e *SyntaxError) Error() string {
	b := []byte("tlv: syntax error")
	if e.Header.Tag != TagEndOfContents {
		b = append(b, " within "...)
		b = append(b, e.Header.String()...)
	}
	if e.ByteOffset > 0 {
		//goland:noinspection GoDirectComparisonOfErrors
		if e.Err == io.ErrUnexpectedEOF {
			b = strconv.AppendInt(append(b, " at offset "...), e.ByteOffset, 10)
		} else {
			b = strconv.AppendInt(append(b, " for TLV beginning at offset "...), e.ByteOffset, 10)
		}
	}
	if e.Err != nil {
		b = append(b, ": "...)
		b = append(b, e.Err.Error()...)
	}
	return string(b)
}

// noEOF returns err, unless err == io.EOF, in which case it returns io.ErrUnexpectedEOF.
func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
