package tlv

import (
	"bufio"
	"io"
	"testing"
)

type indefiniteReader struct {
	data   []byte
	offset int
}

func (r *indefiniteReader) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		b[i] = r.data[(r.offset+i)%len(r.data)]
	}
	r.offset = (r.offset + len(b)) % len(r.data)
	return len(b), nil
}

func BenchmarkDecodePrimitive(b *testing.B) {
	b.SetBytes(3)

	r := indefiniteReader{data: []byte{0x02, 0x01, 0x15}}
	d := NewDecoder(bufio.NewReader(&r))
	var (
		err error
		val io.ReadCloser
	)
	for b.Loop() {
		_, val, err = d.ReadHeader()
		if err != nil {
			b.Fatalf("d.ReadHeader() returned an unexpected error: %q", err)
		}
		if err = val.Close(); err != nil {
			b.Fatalf("val.Close() returned an unexpected error: %q", err)
		}
	}
}

func BenchmarkDecodeConstructed(b *testing.B) {
	run := func(k int) func(*testing.B) {
		return func(b *testing.B) {
			data := make([]byte, 0, 2*k+3)
			for i := k - 1; i >= 0; i-- {
				data = append(data, 0x30, byte(i)*2)
			}
			b.SetBytes(int64(len(data)))

			r := indefiniteReader{data: data}
			d := NewDecoder(bufio.NewReader(&r))
			var err error
			for b.Loop() {
				_, _, err = d.ReadHeader()
				if err != nil {
					b.Fatalf("d.ReadHeader() returned an unexpected error: %q", err)
				}
				if err = d.Skip(); err != nil {
					b.Fatalf("d.Skip() returned an unexpected error: %q", err)
				}
			}
		}
	}

	b.Run("1", run(1))
	b.Run("3", run(3))
	b.Run("10", run(10))
	b.Run("20", run(20))
}
