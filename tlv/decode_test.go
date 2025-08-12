package tlv

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"codello.dev/asn1"
)

// testDataReader implements an [io.Reader] for testing the [Decoder] type. It
// reads data from a slice. The slice can contain values of types byte, int, and
// error. The Read method produces the provided bytes (or ints converted to
// bytes) and errors in the provided order.
type testDataReader struct {
	data []any
}

// Read implements [io.Reader] by producing bytes and errors from r.data.
func (r *testDataReader) Read(p []byte) (n int, err error) {
	for n < len(p) && len(r.data) > 0 && err == nil {
		switch v := r.data[0].(type) {
		case byte:
			p[n] = v
			n++
		case int:
			p[n] = byte(v)
			n++
		case error:
			err = v
		default:
			panic(fmt.Sprintf("invalid data value: %v", v))
		}
		r.data = r.data[1:]
	}
	if len(r.data) == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

// TestReadHeader tests the general reading behavior. Each test case consists of
// an input sequence, an output sequence and an expected offset.
//
//   - The input sequence is as slice of bytes (or integers) and errors. These
//     are the bytes and errors produced by the underlying reader of the [Decoder].
//   - The output sequence is a sequence of values of types [Header], []byte, and
//     error. These are the headers, values and errors produced by subsequent
//     [Decoder.ReadHeader] calls. A value of type []byte is processed together with
//     the [Header] that immediately precedes it.
//   - The expected offset is the expected [Decoder.InputOffset] after the output
//     sequence has been processed.
func TestReadHeader(t *testing.T) {
	// anyError can be used in the want array to match any non-nil error
	var anyError = errors.New("any error")
	// errTransient simulates a transient error
	var errTransient = errors.New("transient error")

	tt := map[string]struct {
		input  []any
		want   []any
		offset int64
	}{
		"SingleValue": {[]any{0x02, 0x01, 0x15},
			[]any{Header{asn1.TagInteger, false, 1}, []byte{0x15}, io.EOF},
			3},
		"MultipleValues": {[]any{0x02, 0x01, 0x15, 0x02, 0x01, 0x03},
			[]any{Header{asn1.TagInteger, false, 1}, []byte{0x15}, Header{asn1.TagInteger, false, 1}, []byte{0x03}, io.EOF},
			6},
		"EmptyConstructed": {[]any{0x30, 0x00},
			[]any{Header{asn1.TagSequence, true, 0}, EndOfContents, io.EOF},
			2},
		"EmptyConstructedIndefinite": {[]any{0x30, 0x80, 0x00, 0x00},
			[]any{Header{asn1.TagSequence, true, LengthIndefinite}, EndOfContents, io.EOF},
			4},
		"Constructed": {[]any{0x30, 0x03, 0x02, 0x01, 0x15},
			[]any{Header{asn1.TagSequence, true, 3}, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, io.EOF},
			5},
		"ConstructedIndefinite": {[]any{0x30, 0x80, 0x02, 0x01, 0x15, 0x00, 0x00},
			[]any{Header{asn1.TagSequence, true, LengthIndefinite}, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, io.EOF},
			7},
		"IndefiniteInDefinite": {[]any{0x30, 0x07, 0x30, 0x80, 0x02, 0x01, 0x15, 0x00, 0x00},
			[]any{Header{asn1.TagSequence, true, 7}, Header{asn1.TagSequence, true, LengthIndefinite}, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, EndOfContents, io.EOF},
			9},

		// Unexpected/Invalid End-of-Contents
		"UnexpectedEOC": {[]any{0x30, 0x03, 0x00, 0x00, 0x00},
			[]any{Header{asn1.TagSequence, true, 3}, errUnexpectedEOC, errUnexpectedEOC},
			2},
		"InvalidEOC": {[]any{0x30, 0x80, 0x00, 0x01, 0x00},
			[]any{Header{asn1.TagSequence, true, LengthIndefinite}, errInvalidEOC, errInvalidEOC},
			2},

		// Testing Tag and Length Values
		"LargeTag": {[]any{0x1F, 0x84, 0x01, 0x00},
			[]any{Header{0x0201, false, 0}, io.EOF},
			4},
		"NonMinimalTag": {[]any{0x1F, 0x80, 0x05, 0x00},
			[]any{anyError},
			0},
		"LargePaddedLength": {[]any{0x04, 0x84, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			[]any{Header{asn1.TagOctetString, false, 3}, []byte{0x01, 0x02, 0x03}, io.EOF},
			9},

		// Structural Errors
		"ChildExceedsParent": {[]any{0x30, 0x03, 0x02, 0x02, 0x15, 0x15},
			[]any{Header{asn1.TagSequence, true, 3}, anyError},
			2},

		// Reader Errors
		"TransientError": {[]any{0x30, errTransient, 0x04, 0x02, 0x81, errTransient, 0x01, 0x15},
			[]any{errTransient, Header{asn1.TagSequence, true, 4}, errTransient, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, io.EOF},
			6},
		"MultipleTransientErrors": {[]any{errTransient, errTransient, 0x30, 0x03, errTransient, 0x02, 0x01, 0x15},
			[]any{errTransient, errTransient, Header{asn1.TagSequence, true, 3}, errTransient, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, io.EOF, io.EOF},
			5},
		"UnexpectedEOF": {[]any{0x30, 0x03, 0x02, 0x01},
			[]any{Header{asn1.TagSequence, true, 3}, Header{asn1.TagInteger, false, 1}, io.ErrUnexpectedEOF},
			4},
	}
	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(&testDataReader{tc.input})
			for i := 0; i < len(tc.want); i++ {
				h, val, err := d.ReadHeader()

				switch want := tc.want[i].(type) {
				case error:
					if err == nil {
						t.Fatalf("d.ReadHeader(): got %s, wanted error", h)
					}
					//goland:noinspection GoDirectComparisonOfErrors
					if want != anyError && !errors.Is(err, want) {
						t.Fatalf("d.ReadHeader(): got %q, wanted %q", err, want)
					}

				case Header:
					// assert h
					if err != nil {
						t.Errorf("d.ReadHeader() produced an unexpected error: %s, expected %v", err, want)
						return
					}
					if !reflect.DeepEqual(h, want) {
						t.Errorf("d.ReadHeader() = %s, want %s", h, want)
						return
					}
					// assert val
					if i+1 >= len(tc.want) {
						// no assertion on value given
						continue
					}
					wantBytes, ok := tc.want[i+1].([]byte)
					if !ok {
						// no assertion on value given
						continue
					}
					i++
					got, err := io.ReadAll(val)
					if err != nil {
						t.Errorf("d.Value() produced an unexpected error: %s", err)
						return
					}
					if !bytes.Equal(got, wantBytes) {
						t.Errorf("d.Value() = %q, want %q", got, wantBytes)
						return
					}

				default:
					t.Fatalf("unexpected type in test case: %T", tc.want[i])
				}
			}
			if d.InputOffset() != tc.offset {
				t.Errorf("d.InputOffset() = %d, want %d", d.InputOffset(), tc.offset)
			}
		})
	}
}

func TestSkip(t *testing.T) {
	tests := map[string]struct {
		input  []byte
		read   int
		err    error
		offset int64
	}{
		"Primitive": {[]byte{0x02, 0x01, 0x15},
			1, nil, 3},
		"Constructed": {[]byte{0x30, 0x06, 0x02, 0x01, 0x15, 0x02, 0x01, 0x16},
			1, nil, 8},
		"Indefinite": {[]byte{0x30, 0x80, 0x02, 0x01, 0x15, 0x00, 0x00},
			1, nil, 7},

		"InnerPrimitive": {[]byte{0x30, 0x03, 0x02, 0x01, 0x15, 0x02, 0x01, 0x16},
			2, nil, 5},

		"UnexpectedEOC": {[]byte{0x30, 0x08, 0x02, 0x01, 0x15, 0x00, 0x00, 0x02, 0x01, 0x16},
			1, errUnexpectedEOC, 5},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(bytes.NewReader(tc.input))
			for range tc.read {
				_, _, err := d.ReadHeader()
				if err != nil {
					t.Fatalf("d.ReadHeader() returned an unexpected error: %s", err)
				}
			}
			err := d.Skip()
			if !errors.Is(err, tc.err) {
				t.Errorf("d.Skip() produced an unexpected error: %s, expected %s", err, tc.err)
			}
			if d.InputOffset() != tc.offset {
				t.Errorf("d.InputOffset() = %d, want %d", d.InputOffset(), tc.offset)
			}
		})
	}
}

func TestStack(t *testing.T) {
	tests := map[string]struct {
		input  []byte
		want   Header
		depth  int
		offset int64
	}{
		"Root": {[]byte{},
			Header{0, true, LengthIndefinite}, 0, 0},
		"RootAfterElement": {[]byte{0x02, 0x01, 0x15},
			Header{0, true, LengthIndefinite}, 0, 3},
		"SingleValue": {[]byte{0x02, 0x01},
			Header{asn1.TagInteger, false, 1}, 1, 2},
		"NestedConstructed": {[]byte{0x30, 0x05, 0x30, 0x03, 0x24, 0x01},
			Header{asn1.TagOctetString, true, 1}, 3, 6},
		"InvalidLength": {[]byte{0x30, 0x05, 0x04, 0x80, 0x01, 0x00, 0x00},
			Header{asn1.TagSequence, true, 5}, 1, 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(bytes.NewReader(tc.input))
			var err error
			for err == nil {
				_, _, err = d.ReadHeader()
			}
			if d.StackDepth() != tc.depth {
				t.Errorf("d.StackDepth() = %d, want %d", d.StackDepth(), tc.depth)
			}
			if d.StackIndex(d.StackDepth()) != tc.want {
				t.Errorf("d.StackIndex(...) = %s, want %s", d.StackIndex(d.StackDepth()), tc.want)
			}
			if d.InputOffset() != tc.offset {
				t.Errorf("d.InputOffset() = %d, want %d", d.InputOffset(), tc.offset)
			}
		})
	}
}
