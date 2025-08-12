package tlv

import (
	"errors"
	"io"
)

//region Read Helpers

// byteReader is the base reader type needed for [Decoder] and [Value].
type byteReader interface {
	io.Reader
	io.ByteReader
}

// byteReaderFunc is a function that can read a single byte from an underlying
// byte stream. It implements [io.ByteReader].
type byteReaderFunc func() (byte, error)

func (f byteReaderFunc) ReadByte() (byte, error) { return f() }

//endregion

//region bufferedReader

// maxConsecutiveEmptyReads is the maximum number of empty reads before
// [bufferedReader] returns an error from its Read method.
const maxConsecutiveEmptyReads = 100

// errNegativeRead indicates that a reader returned a negative number from its
// Read method.
var errNegativeRead = errors.New("tlv: reader returned negative count from Read")

// bufferedReader works similar to the [bufio.Reader] type but supports an
// additional limit that controls how far buffer fills may read ahead.
//
// The limit is controlled via the [bufferedReader.Limit] and
// [bufferedReader.SetLimit] methods.
//
//   - A limit of 0 indicates that no reading ahead is allowed. Reading from the
//     bufferedReader will directly read from the underlying reader.
//   - A limit of -1 indicates that buffer fills may read arbitrarily far ahead.
//   - Any other positive limit indicates the number of bytes that may be read
//     during buffer fills.
//
// Note that even for a limit of 0, read operations may read buffered data, if
// the buffer is already filled.
type bufferedReader struct {
	rd   io.Reader
	buf  []byte
	r, w int // buf read and write positions
	lim  int // number of bytes we are allowed to buffer from rd
	err  error
}

// Reset resets b to read from r. The buffer of b will be reused but its
// contents are discarded.
func (b *bufferedReader) Reset(r io.Reader) {
	b.rd = r
	if b.buf == nil && r != nil {
		b.buf = make([]byte, 1024)
	}
	b.r = 0
	b.w = 0
	b.lim = 0
}

// SetLimit configures the buffer limit of b. b will not read more than n bytes
// ahead from the current position to fill its buffer. If b has already buffered
// more than n bytes, it will not buffer any additional bytes (unless a new
// limit is set).
func (b *bufferedReader) SetLimit(n int) { b.lim = n }

// Limit returns the current buffer limit of b. The buffer limit is the number
// of bytes that b is allowed to read ahead of the current position. A limit of
// 0 indicates that b is not allowed to read ahead. A limit of -1 indicates that
// b may read arbitrarily far.
//
// Note that the value returned by this method is always relative to the current
// read position. The value may differ from the limit set via
// [bufferedReader.SetLimit].
func (b *bufferedReader) Limit() int { return b.lim }

// fill reads a new chunk into the buffer.
func (b *bufferedReader) fill() {
	// Slide existing data to beginning.
	if b.r > 0 {
		copy(b.buf, b.buf[b.r:b.w])
		b.w -= b.r
		b.r = 0
	}

	if b.w >= len(b.buf) {
		panic("tlv: tried to fill full buffer")
	}

	// Read new data: try a limited number of times.
	for i := maxConsecutiveEmptyReads; i > 0; i-- {
		n, err := b.rd.Read(b.buf[b.w:MinLength(len(b.buf), b.lim)])
		if n < 0 {
			panic(errNegativeRead)
		}
		b.w += n
		b.lim = max(b.lim-n, LengthIndefinite)
		if err != nil {
			b.err = err
			return
		}
		if n > 0 {
			return
		}
	}
	b.err = io.ErrNoProgress
}

// readErr returns any error encountered during the last fill operation.
func (b *bufferedReader) readErr() error {
	err := b.err
	b.err = nil
	return err
}

// Buffered returns the number of bytes that are currently in the buffer.
func (b *bufferedReader) Buffered() int { return b.w - b.r }

// Read implements [io.Reader].
func (b *bufferedReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		if b.Buffered() > 0 {
			return 0, nil
		}
		return 0, b.readErr()
	}
	if b.r == b.w {
		if b.err != nil {
			return 0, b.readErr()
		}
		if len(p) >= len(b.buf) || b.lim == 0 {
			// Read directly into p to avoid copy.
			n, b.err = b.rd.Read(p)
			if n < 0 {
				panic(errNegativeRead)
			}
			return n, b.readErr()
		}
		// One read.
		// Do not use b.fill, which will loop.
		b.r = 0
		b.w = 0
		n, b.err = b.rd.Read(b.buf[:MinLength(len(b.buf), b.lim)])
		if n < 0 {
			panic(errNegativeRead)
		}
		if n == 0 {
			return 0, b.readErr()
		}
		b.w += n
		b.lim = max(b.lim-n, LengthIndefinite)
	}

	n = copy(p, b.buf[b.r:b.w])
	b.r += n
	return n, nil
}

// ReadByte implements [io.ByteReader].
func (b *bufferedReader) ReadByte() (byte, error) {
	for b.r == b.w {
		if b.err != nil {
			return 0, b.readErr()
		}
		if b.lim == 0 {
			if br, ok := b.rd.(io.ByteReader); ok {
				return br.ReadByte()
			}
			var bs [1]byte
			_, err := io.ReadFull(b.rd, bs[:1])
			return bs[0], err
		}
		b.fill()
	}
	c := b.buf[b.r]
	b.r++
	return c, nil
}

// Discard discards up to n bytes from v. It returns the number of bytes
// discarded. An error is returned iff discarded < n.
//
// If the underlying reader of r implements its own Discard method it will be
// used for more efficient discarding.
func (b *bufferedReader) Discard(n int) (discarded int, err error) {
	if n < 0 {
		return 0, errors.New("negative count")
	}
	if n == 0 {
		return
	}

	b.lim = max(b.lim, n)
	for discarded < n {
		if b.w > b.r {
			skip := min(n-discarded, b.Buffered())
			b.r += skip
			discarded += skip
			continue
		}
		if b.err != nil {
			return discarded, b.readErr()
		}
		switch rd := b.rd.(type) {
		case interface{ Discard(int) (int, error) }:
			var d int
			d, b.err = rd.Discard(n - discarded)
			discarded += d
		default:
			// we have set b.lim above so filling the buffer is fine
			b.fill()
		}
	}
	return discarded, nil
}

// discard discards up to n bytes from v. It returns the number of bytes
// discarded. An error is returned iff discarded < n.
//
// If the underlying reader of r implements its own Discard method it will be
// used for more efficient discarding.
func discard(r io.Reader, n int) (discarded int, err error) {
	switch rd := r.(type) {
	case interface{ Discard(int) (int, error) }:
		discarded, err = rd.Discard(n)
	default:
		var d int64
		d, err = io.CopyN(io.Discard, rd, int64(n))
		discarded = int(d)
	}
	return discarded, err
}

//endregion

//endregion
