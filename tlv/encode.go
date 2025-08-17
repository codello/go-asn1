package tlv

import (
	"errors"
	"io"
	"math/bits"

	"codello.dev/asn1/internal/vlq"
)

//region valueWriter

// valueWriter represents a primitive TLV value for writing. It implements
// [io.Writer] among others. The writer is restricted to write at most n bytes
// (corresponding to the length of the value).
//
// For primitive data values at the root level valueWriter takes care of
// flushing the internal buffer of [Encoder]. In case of errors during flushing,
// additional flushes can be triggered via empty writes.
//
// Errors from the underlying writer may be wrapped before being returned.
type valueWriter struct {
	e *Encoder
	n int // remaining number of bytes
}

// Len returns the number of bytes in the unwritten portion of the value.
func (w *valueWriter) Len() int {
	return max(w.n, 0)
}

// WriteByte implements [io.ByteReader].
func (w *valueWriter) WriteByte(b byte) error {
	if w.n < 0 {
		return errClosed
	}
	if w.Len() == 0 {
		return errTruncated
	}
	err := w.e.wr.WriteByte(b)
	if err != nil {
		return &ioError{"write", err}
	}
	w.n--
	return nil
}

// Write implements [io.Writer].
func (w *valueWriter) Write(p []byte) (n int, err error) {
	if w.n < 0 {
		return 0, errClosed
	}
	write := min(len(p), w.Len())
	if write > 0 {
		n, err = w.e.wr.Write(p[:write])
	}
	w.n -= n
	if err != nil {
		err = &ioError{"write", err}
	} else if n < write {
		err = &ioError{"write", io.ErrShortWrite}
	} else if write < len(p) {
		err = errTruncated
	}
	return n, err
}

// Close finishes writing the data value and updates the state of the underlying
// Encoder. If this is not a root element, Close will never return an error.
func (w *valueWriter) Close() error {
	if w.n < 0 {
		return errClosed
	} else if w.Len() > 0 {
		return errors.New("tlv: value not fully written")
	}
	w.n = -1
	return w.e.valueDone()
}

//endregion

//region Encoder

// Encoder is a streaming encoder for the TLV format used by ASN.1 encoding
// rules such as BER, DER or CER. It is used to write a stream of top-level
// tag-length-value (TLV) constructs.
//
// Encoder can be used in presence of transient errors from the underlying
// writer. If an error occurs, the encoder is - in effect - reset to the state
// before the last WriteHeader call.
type Encoder struct {
	state
	wr interface {
		io.Writer
		io.ByteWriter
	}
	buf bufferedWriter // internal buffering
	val *valueWriter

	// Headers are first encoded into peekBuf and then written to the underlying
	// writer. If the underlying writer does not successfully complete the write
	// operation, peekBuf[:peekLen] contains the bytes that were not written. A
	// repeat-call to WriteHeader using the same value as before (stored as
	// peekHeader) will attempt to write the peekBuf bytes (instead of re-encoding
	// the full peekHeader).
	//
	// The maximum number of bytes for a valid header is 12:
	//   - 1 identifier byte
	//   - 2 bytes for the long-form tag
	//   - 1 byte for the number of length bytes
	//   - up to 8 length bytes (64 bit int)

	peekHeader Header
	peekBuf    [12]byte
	peekAt     int8
	peekLen    int8
}

// NewEncoder creates a new [Encoder] writing to w. If w does not implement
// [io.ByteWriter], Encoder will do its own buffering. The buffer is
// automatically flushed at the end of each top-level data value.
func NewEncoder(w io.Writer) *Encoder {
	e := new(Encoder)
	e.Reset(w)
	return e
}

// Reset resets the state of e to write to w. See [NewEncoder] for details.
//
// Reset reuses the internal buffer of e which may save some allocations
// compared to [NewEncoder].
func (e *Encoder) Reset(w io.Writer) {
	e.state.reset()

	if bw, ok := w.(interface {
		io.Writer
		io.ByteWriter
	}); ok {
		// allow previous writer to be garbage-collected, but keep the allocated buffer
		e.buf.Reset(nil)
		e.wr = bw
	} else {
		e.buf.Reset(w)
		e.wr = &e.buf
	}
	e.val = nil

	e.peekLen = 0
}

// WriteHeader writes the next TLV header to the output. At the end of
// constructed TLVs, a Header with [TagEndOfContents] must be written (for both
// definite and indefinite-length encodings). Encoder validates that the written
// sequence of headers and values is valid and will return an error if h cannot
// be written at the current place in the TLV structure.
//
// If h indicates the use of the primitive encoding, WriteHeader returns an
// [io.WriteCloser] that can be used to write the contents of the value. It also
// implements [io.ByteWriter]. Before the next call to WriteHeader, the full
// value (as indicated by h.Length) must be written and [io.Closer.Close] must
// be called.
//
// WriteHeader can be used in presence of transient errors. If the underlying
// writer returns an error during the write operation, WriteHeader will return
// that error (potentially wrapped). If the underlying writer maintains a
// consistent state after an error, you can retry the WriteHeader operation
// (using the same value for h) to resume the previous write operation.
func (e *Encoder) WriteHeader(h Header) (io.WriteCloser, error) {
	if e.val != nil {
		return nil, errors.New("tlv: value not closed")
	}
	err := e.writeHeader(h)
	if err != nil {
		if _, ok := err.(*ioError); !ok {
			// We haven't actually written any data, which means h was invalid, or we got
			// truncated. Reset peek buffer so that it can be filled on the next call
			e.peekLen = 0
			e.peekAt = 0
			err = &SyntaxError{ByteOffset: e.offset, Header: e.curr.Header, Err: err}
		}
		return nil, err
	}

	if h.Tag == TagEndOfContents {
		e.state.pop(int(e.peekAt))
	} else {
		e.state.push(h, int(e.peekAt))
	}
	// successfully written, invalidate peek
	e.peekLen = 0
	e.peekAt = 0

	// when using buffering we prefer to write complete headers/values
	e.buf.Flushable()

	if h.Constructed || h.Tag == TagEndOfContents {
		return nil, nil
	}
	e.val = &valueWriter{e, e.curr.Remaining()}
	return e.val, nil
}

// writeHeader encodes a TLV header into e. If encoding fails or h is not a
// valid next TLV, an error is returned.
func (e *Encoder) writeHeader(h Header) error {
	if h.Tag == TagEndOfContents {
		switch {
		case h != Header{}:
			return errInvalidEOC
		case e.state.root() || !e.curr.Constructed:
			return errUnexpectedEOC
		case e.curr.Header.Length != LengthIndefinite && e.curr.Remaining() != 0:
			return errUnexpectedEOC
		}
		if e.curr.Header.Length == LengthIndefinite {
			if err := e.encodeHeader(h); err != nil {
				return err
			}
		}
		if e.StackDepth() == 1 {
			// We have ended a top level data value
			if err := e.buf.Flush(); err != nil {
				return &ioError{"write", err}
			}
		}
		return nil
	}

	if !h.Constructed && h.Length == LengthIndefinite {
		return errors.New("indefinite-length primitive data value")
	} else if h.Length != LengthIndefinite && uint(HeaderSize(h)+h.Length) > uint(e.curr.Remaining()) {
		return errors.New("data value exceeds parent")
	}

	return e.encodeHeader(h)
}

// encodeHeader encodes h into the TLV format. Data is written using writeByte
// into e.peekBuf and then flushed to the underlying writer. If a previous call
// has left-over data in e.peekBuf, that data is written instead (as long as h
// matches e.peekHeader, that generated the data).
func (e *Encoder) encodeHeader(h Header) (err error) {
	defer func() {
		if err == nil {
			err = e.flush()
		}
	}()

	if e.peekLen > 0 {
		// we have unwritten data from the last call
		if h != e.peekHeader {
			return errors.New("unwritten data after write error")
		}
		return nil
	}
	e.peekHeader = h

	b := uint8(h.Tag.Class() >> 8)
	if h.Constructed {
		b |= 0x20
	}
	if h.Tag.Number() < 31 {
		b |= uint8(h.Tag.Number())
		if err = e.writeByte(b); err != nil {
			return err
		}
	} else {
		b |= 0x1f
		if err = e.writeByte(b); err != nil {
			return err
		}
		if _, err = vlq.Write(byteWriterFunc(e.writeByte), h.Tag.Number()); err != nil {
			return err
		}
	}

	if h.Length == LengthIndefinite {
		return e.writeByte(0x80)
	} else if h.Length >= 128 {
		numBytes := (bits.Len(uint(h.Length)) + 7) / 8
		err = e.writeByte(0x80 | byte(numBytes))
		for ; numBytes > 0 && err == nil; numBytes-- {
			err = e.writeByte(byte(h.Length >> uint((numBytes-1)*8)))
		}
		return err
	}
	return e.writeByte(byte(h.Length))
}

// writeByte writes byte b into the internal retry buffer e.peekBuf.
func (e *Encoder) writeByte(b byte) error {
	if int(e.peekLen) == e.curr.Remaining() {
		return errTruncated
	}
	e.peekBuf[e.peekLen] = b
	e.peekLen++
	return nil
}

// flush writes the internal retry buffer e.peekBuf into the underlying writer.
// If an error occurs, the remaining data is shifted to the front of e.peekBuf
// and the error is returned.
func (e *Encoder) flush() error {
	if e.peekAt == e.peekLen {
		return nil // avoid empty writes
	}
	n, err := e.wr.Write(e.peekBuf[e.peekAt:e.peekLen])
	e.peekAt += int8(n)
	if err != nil {
		err = &ioError{"write", err}
	}
	return err
}

// valueDone gets called by the valueWriter type when a data value has been
// fully written. e automatically updates its state accordingly.
func (e *Encoder) valueDone() error {
	if e.val.Len() != 0 {
		panic("BUG: value is not completely written")
	}
	if e.StackDepth() == 1 {
		// we have finished a root data value
		if err := e.buf.Flush(); err != nil {
			return &ioError{"write", err}
		}
	}
	e.val = nil

	// We have written the entire data value.
	// Next another TLV header must follow.
	e.state.pop(e.curr.Remaining())
	return nil
}

// DataValueOffset returns the output byte offset where the current data value
// begins. This is the first byte of the identifier octets of the current data
// value.
func (e *Encoder) DataValueOffset() int64 {
	return e.curr.Start
}

// OutputOffset returns the current output byte offset. It gives the location of
// the next byte immediately after the most recently written header or value.
// The number of bytes actually written to the underlying [io.Writer] may be
// less than this offset due to internal buffering effects.
func (e *Encoder) OutputOffset() int64 {
	if e.val != nil {
		// this never happens if d.curr.Length is indefinite
		return e.offset + int64(e.curr.Length-e.val.Len())
	}
	return e.offset + int64(e.peekAt)
}

// StackDepth returns the depth of nested constructed TLVs that have been opened
// and not closed by WriteHeader. Each level on the stack represents a
// constructed TLV. It is incremented whenever a constructed TLV is encountered
// by WriteHeader and decremented whenever the corresponding EndOfContents is
// encountered. The depth is zero-indexed, where zero represents the (virtual)
// top-level TLV.
func (e *Encoder) StackDepth() int { return len(e.stack) }

// StackIndex returns information about the specified stack level.
// It must be a number between 0 and [Encoder.StackDepth], inclusive.
//
// The TLV header at level 0 represents the top level and is not written to the
// output. The top-level TLV header is a constructed, indefinite-length data
// value with tag 0.
func (e *Encoder) StackIndex(i int) Header {
	if i == len(e.stack) {
		return e.curr.Header
	}
	return e.stack[i].Header
}

//endregion
