package tlv

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"codello.dev/asn1"
)

type testErrorWriter struct {
	wr interface {
		io.Writer
		io.ByteWriter
	}
	n   int
	err error
}

func (w *testErrorWriter) WriteByte(c byte) error {
	if w.n == 0 && w.err != nil {
		err := w.err
		w.err = nil
		return err
	}
	err := w.wr.WriteByte(c)
	if err != nil {
		w.n -= 1
	}
	return err
}

func (w *testErrorWriter) Write(p []byte) (int, error) {
	if w.n == 0 && w.err != nil {
		err := w.err
		w.err = nil
		return 0, err
	}
	if w.n > 0 && len(p) > w.n {
		p = p[:w.n]
	}
	n, err := w.wr.Write(p)
	w.n -= n
	if w.n == 0 && err == nil {
		err = w.err
		w.err = nil
	}
	return n, err
}

type transientError int

func (e transientError) Error() string {
	return "transient error"
}

func TestWriteHeader(t *testing.T) {
	tests := map[string]struct {
		input   []any
		buffer  bool // use builtin buffering
		want    []byte
		wantErr error
	}{
		"SingleValue": {[]any{Header{asn1.TagInteger, false, 1}, []byte{0x15}}, true,
			[]byte{0x02, 0x01, 0x15}, nil},
		"ConstructedValue": {[]any{Header{asn1.TagSequence, true, 3}, Header{asn1.TagOctetString, false, 1}, []byte{0x15}, EndOfContents}, true,
			[]byte{0x30, 0x03, 0x04, 0x01, 0x15}, nil},
		"IndefiniteLength": {[]any{Header{asn1.TagSequence, true, LengthIndefinite}, Header{asn1.TagOctetString, false, 1}, []byte{0x15}, EndOfContents}, true,
			[]byte{0x30, 0x80, 0x04, 0x01, 0x15, 0x00, 0x00}, nil},

		"LargeTag": {[]any{Header{215, false, 0}}, false,
			[]byte{0x1f, 0x81, 0x57, 0x00}, nil},
		"LargeLength": {[]any{Header{asn1.TagSet, true, 1000}}, false,
			[]byte{0x31, 0x82, 0x03, 0xE8}, nil},

		"UnexpectedEOC": {[]any{Header{asn1.TagSequence, true, 15}, EndOfContents}, false,
			[]byte{0x30, 0x0F}, errUnexpectedEOC},

		// transient errors
		"TransientBeforeHeader": {[]any{transientError(0), Header{asn1.TagSequence, true, 3}, transientError(0), Header{asn1.TagOctetString, false, 1}, []byte{0x15}, EndOfContents}, true,
			[]byte{0x30, 0x03, 0x04, 0x01, 0x15}, nil},
		"TransientInHeader": {[]any{transientError(1), Header{asn1.TagInteger, false, 1}, []byte{0x15}}, false,
			[]byte{0x02, 0x01, 0x15}, nil},
		"TransientBuffered": {[]any{Header{asn1.TagSequence, true, 3}, Header{asn1.TagOctetString, false, 1}, []byte{0x15}, transientError(0), EndOfContents}, true,
			[]byte{0x30, 0x03, 0x04, 0x01, 0x15}, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := bytes.Buffer{}
			got.Grow(len(tc.want))
			wr := &testErrorWriter{wr: &got}
			var w io.Writer = wr
			if tc.buffer {
				w = io.MultiWriter(w)
			}
			e := NewEncoder(w)

			var err error
		loop:
			for i := 0; i < len(tc.input) && err == nil; i++ {
				switch h := tc.input[i].(type) {
				case Header:
					var value io.Writer
					value, err = e.WriteHeader(h)
					var tErr transientError
					if errors.As(err, &tErr) {
						// retry after transient error
						err = nil
						i--
						continue
					}
					if err != nil {
						break loop
					}
					if i+1 >= len(tc.input) {
						// no more values
						continue
					}
					data, ok := tc.input[i+1].([]byte)
					if !ok {
						// no value given
						continue
					}
					i++
					if value == nil {
						t.Errorf("e.WriteHeader() did not return a value writer, expected non-nil value")
						break loop
					}
					_, err = value.Write(data)

				case transientError:
					wr.err = h
					wr.n = int(h)

				case error:
					wr.err = h

				default:
					panic(fmt.Sprintf("invalid input type %T", h))
				}
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("WriteHeader(): got %q, want %q", err, tc.wantErr)
			}
			if !bytes.Equal(got.Bytes(), tc.want) {
				t.Errorf("WriteHeader(): got %# x, want %# x", got.Bytes(), tc.want)
			}
		})
	}
}
