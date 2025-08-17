package tlv

import (
	"bytes"
	"io"
	"testing"

	"codello.dev/asn1"
)

func BenchmarkEncodePrimitive(b *testing.B) {
	var out bytes.Buffer
	out.Grow(3)
	e := NewEncoder(&out)
	var val io.WriteCloser
	var err error
	b.SetBytes(3)
	for b.Loop() {
		out.Reset()
		val, err = e.WriteHeader(Header{asn1.TagInteger, false, 1})
		if err != nil {
			b.Fatalf("WriteHeader() returned an unexpected error: %v", err)
		}
		if err = val.(io.ByteWriter).WriteByte(0x15); err != nil {
			b.Fatalf("WriteByte() returned an unexpected error: %v", err)
		}
		if err = val.Close(); err != nil {
			b.Fatalf("Close() returned an unexpected error: %v", err)
		}
	}
}

func BenchmarkEncodeConstructed(b *testing.B) {
	run := func(k int) func(*testing.B) {
		return func(b *testing.B) {
			var out bytes.Buffer
			out.Grow(k * 2)
			e := NewEncoder(&out)
			b.SetBytes(int64(k * 2))

			var err error
			for b.Loop() {
				out.Reset()
				for i := k - 1; i >= 0; i-- {
					if _, err = e.WriteHeader(Header{asn1.TagSequence, true, 2 * i}); err != nil {
						b.Fatalf("WriteHeader() returned an unexpected error: %v", err)
					}
				}
				for range k {
					if _, err = e.WriteHeader(Header{}); err != nil {
						b.Fatalf("WriteHeader() returned an unexpected error: %v", err)
					}
				}
			}
		}
	}

	b.Run("1", run(1))
	b.Run("3", run(3))
	b.Run("10", run(10))
	b.Run("20", run(20))
}
