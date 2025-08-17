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

func TestEncoder_WriteHeader(t *testing.T) {
	anyError := errors.New("any error")

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
		"Truncated": {[]any{Header{asn1.TagSequence, true, 1}, Header{asn1.TagInteger, false, 1}}, false,
			[]byte{0x30, 0x01}, anyError},
		"ElementInEmptyConstructed": {[]any{Header{asn1.TagSequence, true, 0}, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents}, false,
			[]byte{0x30, 0x00}, anyError},

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
			var val io.WriteCloser
			var op string
			for i := 0; i < len(tc.input) && err == nil; i++ {
				switch h := tc.input[i].(type) {
				case Header:
					op = "e.WriteHeader"
					val, err = e.WriteHeader(h)

				case []byte:
					op = "value.Write"
					if val == nil {
						t.Fatalf("e.WriteHeader() did not return a value writer, expected non-nil value")
					}
					var n int
					n, err = val.Write(h)
					tc.input[i] = h[n:]
					if err == nil {
						err = val.Close()
					}

				case error:
					var tErr transientError
					if errors.Is(h, &tErr) {
						wr.err = h
						wr.n = int(tErr)
					} else {
						wr.err = h
					}

				default:
					panic(fmt.Sprintf("invalid input type %T", h))
				}

				var tErr transientError
				if errors.As(err, &tErr) {
					// retry after transient error
					err = nil
					i--
					continue
				}
			}
			//goland:noinspection GoDirectComparisonOfErrors
			if !errors.Is(err, tc.wantErr) && !(err != nil && tc.wantErr == anyError) {
				t.Errorf("%s(): got %q, want %q", op, err, tc.wantErr)
			}
			if !bytes.Equal(got.Bytes(), tc.want) {
				t.Errorf("WriteHeader(): got %# x, want %# x", got.Bytes(), tc.want)
			}
			if e.OutputOffset() != int64(len(tc.want)) {
				t.Errorf("OutputOffset(): got %d, want %d", e.OutputOffset(), len(tc.want))
			}
		})
	}
}

func TestSequence(t *testing.T) {
	encodeInt := func(enc *Encoder) error {
		val, err := enc.WriteHeader(Header{asn1.TagInteger, false, 1})
		if err != nil {
			return err
		}
		if err = val.(io.ByteWriter).WriteByte(0x15); err != nil {
			return err
		}
		return val.Close()
	}

	encodeEmptySequence := func(enc *Encoder) error {
		_, err := enc.WriteHeader(Header{asn1.TagSequence, true, LengthIndefinite})
		if err != nil {
			return err
		}
		_, err = enc.WriteHeader(Header{})
		return err
	}

	t.Run("SingleLevelDefinite", func(t *testing.T) {
		var got bytes.Buffer
		want := []byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x02, 0x01, 0x15}
		enc := NewEncoder(&got)
		seq := Sequence{Tag: asn1.TagSequence}
		seq.Append(encodeInt, encodeInt)
		if err := seq.WriteTo(enc); err != nil {
			t.Fatalf("Sequence.WriteTo() returned an unexpected error: %q", err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("Sequence: got %# x, want %# x", got.Bytes(), want)
		}
	})

	t.Run("SingleLevelIndefinite", func(t *testing.T) {
		var got bytes.Buffer
		want := []byte{0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x02, 0x01, 0x15, 0x00, 0x00}
		enc := NewEncoder(&got)
		seq := Sequence{Tag: asn1.TagSequence}
		seq.Append(encodeEmptySequence, encodeInt)
		if err := seq.WriteTo(enc); err != nil {
			t.Fatalf("Sequence.WriteTo() returned an unexpected error: %q", err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("Sequence.WriteTo(): got %# x, want %# x", got.Bytes(), want)
		}
	})

	t.Run("NestedDefinite", func(t *testing.T) {
		var got bytes.Buffer
		want := []byte{0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x15, 0x02, 0x01, 0x15}
		enc := NewEncoder(&got)
		seq := Sequence{Tag: asn1.TagSequence}
		seq.Append(func(enc *Encoder) error {
			seq := Sequence{Tag: asn1.TagSequence}
			seq.Append(encodeInt)
			return seq.WriteTo(enc)
		})
		seq.Append(encodeInt)
		if err := seq.WriteTo(enc); err != nil {
			fmt.Printf("%# x\n", got.Bytes())
			t.Fatalf("Sequence.WriteTo() returned an unexpected error: %q", err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("Sequence.WriteTo(): got %# x, want %# x", got.Bytes(), want)
		}
	})
}

func ExampleSequence() {
	var out bytes.Buffer
	enc := NewEncoder(&out)
	seq := Sequence{Tag: asn1.TagSequence}
	// append a value to the sequence
	seq.Append(func(enc *Encoder) error {
		val, err := enc.WriteHeader(Header{asn1.TagInteger, false, 1})
		if err != nil {
			return err
		}
		err = val.(io.ByteWriter).WriteByte(0x15)
		if err != nil {
			return err
		}
		return val.Close()
	})
	if err := seq.WriteTo(enc); err != nil {
		panic(err)
	}
	fmt.Printf("%# x\n", out.Bytes())
	// Output: 0x30 0x03 0x02 0x01 0x15
}
