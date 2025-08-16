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
func TestDecoder_ReadHeader(t *testing.T) {
	// noError can be used in the input array to assert the error of the previous operation
	var noError error = nil
	// otherError can be used in the want array to match any non-nil, non-EOF, non-syntax error
	var otherError = errors.New("any error")
	// errTransient simulates a transient error
	var errTransient = errors.New("transient error")

	tt := map[string]struct {
		input  []any
		want   []any
		offset int64
	}{
		"SingleValue": {[]any{0x02, 0x01, 0x15},
			[]any{Header{asn1.TagInteger, false, 1}, []byte{0x15}, noError, io.EOF},
			3},
		"MultipleValues": {[]any{0x02, 0x01, 0x15, 0x02, 0x01, 0x03},
			[]any{Header{asn1.TagInteger, false, 1}, []byte{0x15}, Header{asn1.TagInteger, false, 1}, []byte{0x03}, noError, io.EOF},
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
		"IndefiniteInDefiniteNoEnd": {[]any{0x30, 0x05, 0x30, 0x80, 0x02, 0x01, 0x15},
			[]any{Header{asn1.TagSequence, true, 5}, Header{asn1.TagSequence, true, LengthIndefinite}, Header{asn1.TagInteger, false, 1}, []byte{0x15}, noError, &SyntaxError{}},
			7},

		// Unexpected/Invalid End-of-Contents
		"UnexpectedEOC": {[]any{0x30, 0x03, 0x00, 0x00, 0x00},
			[]any{Header{asn1.TagSequence, true, 3}, errUnexpectedEOC, errUnexpectedEOC},
			2},
		"InvalidEOC": {[]any{0x30, 0x80, 0x00, 0x01, 0x00},
			[]any{Header{asn1.TagSequence, true, LengthIndefinite}, errInvalidEOC, errInvalidEOC},
			2},

		// Testing Tag and Length Values
		"LargeTag": {[]any{0x1F, 0x84, 0x01, 0x00},
			[]any{Header{0x0201, false, 0}, []byte{}, noError, io.EOF},
			4},
		"NonMinimalTag": {[]any{0x1F, 0x80, 0x05, 0x00},
			[]any{&SyntaxError{}},
			0},
		"LargePaddedLength": {[]any{0x04, 0x84, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			[]any{Header{asn1.TagOctetString, false, 3}, []byte{0x01, 0x02, 0x03}, noError, io.EOF},
			9},

		// Structural Errors
		"ChildExceedsParent": {[]any{0x30, 0x03, 0x02, 0x02, 0x15, 0x15},
			[]any{Header{asn1.TagSequence, true, 3}, &SyntaxError{}},
			2},

		// Reader Errors
		"TransientError": {[]any{0x30, errTransient, 0x04, 0x02, 0x81, errTransient, 0x01, 0x15},
			[]any{errTransient, Header{asn1.TagSequence, true, 4}, errTransient, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, io.EOF},
			6},
		"MultipleTransientErrors": {[]any{errTransient, errTransient, 0x30, 0x03, errTransient, 0x02, 0x01, 0x15},
			[]any{errTransient, errTransient, Header{asn1.TagSequence, true, 3}, errTransient, Header{asn1.TagInteger, false, 1}, []byte{0x15}, EndOfContents, io.EOF, io.EOF},
			5},
		"UnexpectedEOF": {[]any{0x30, 0x03, 0x02, 0x01},
			[]any{Header{asn1.TagSequence, true, 3}, Header{asn1.TagInteger, false, 1}, []byte{}, io.ErrUnexpectedEOF},
			4},
	}
	for name, tc := range tt {
		isError := func(err any) bool {
			_, ok := err.(error)
			return ok
		}
		isBytes := func(bs any) bool {
			_, ok := bs.([]byte)
			return ok
		}

		t.Run(name, func(t *testing.T) {
			d := NewDecoder(&testDataReader{tc.input})
			var val io.ReadCloser
			var err error
			var got any
			for i := range tc.want {
				switch want := tc.want[i].(type) {
				case error:
					var op string
					if i > 0 && isBytes(tc.want[i-1]) {
						// expected error during last value read
						// err is already set
						op = "valueReader.Read"
					} else {
						// expect error during next ReadHeader()
						got, _, err = d.ReadHeader()
						op = "d.ReadHeader"
					}

					if err == nil {
						t.Fatalf("%s(): got %q, wanted %q", op, got, want)
					}
					var ok bool
					var sErr *SyntaxError
					if err == io.EOF {
						ok = want == io.EOF
					} else if errors.Is(err, want) {
						ok = true
					} else if errors.As(err, &sErr) {
						ok = errors.As(want, &sErr)
					} else {
						//goland:noinspection GoDirectComparisonOfErrors
						ok = want == otherError
					}
					if !ok {
						t.Fatalf("%s(): got %q, wanted %q", op, err, want)
					}

					err = nil

				case Header:
					var h Header
					h, val, err = d.ReadHeader()
					if err != nil {
						t.Fatalf("d.ReadHeader(): returned an unexpected error %q, want %s", err, want)
					}
					if !reflect.DeepEqual(h, want) {
						t.Fatalf("d.ReadHeader() = %s, want %s", h, want)
					}

				case []byte:
					if val == nil {
						t.Fatalf("d.ReadHeader(): returned no value, wanted non-nil io.ReadCloser")
					}
					got, err = io.ReadAll(val)
					if err == nil {
						err = val.Close()
					}
					if i+1 >= len(tc.want) || !isError(tc.want[i+1]) {
						// no errors assertion given, implied no error
						if err != nil {
							t.Fatalf("valueReader.Read() produced an unexpected error: %q", err)
						}
					}
					if !bytes.Equal(got.([]byte), want) {
						t.Fatalf("valueReader.Read() = %q, want %q", got, want)
					}

				case nil:
					// nil can be used after []byte to assert following ReadHeader errors.

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

func TestDecoder_PeekHeader(t *testing.T) {
	data := []byte{0x30, 0x07, 0x30, 0x80, 0x02, 0x01, 0x15, 0x00, 0x00}
	d := NewDecoder(bytes.NewReader(data))
	for i := 3; i >= 0; i-- {
		h, err := d.PeekHeader()
		if i == 0 {
			h, _, err = d.ReadHeader()
		}
		if err != nil {
			t.Fatalf("d.PeekHeader() [%d]: got %v, want nil", i, err)
		}
		if h != (Header{asn1.TagSequence, true, 7}) {
			t.Errorf("d.PeekHeader() [%d]: got %v, want %v", i, h, Header{asn1.TagSequence, true, 7})
		}
		if i > 0 && d.InputOffset() != 0 {
			t.Errorf("d.InputOffset() [%d] = %d, want 0", i, d.InputOffset())
		}
	}
	if d.InputOffset() != 2 {
		t.Errorf("d.InputOffset() = %d, want 2", d.InputOffset())
	}
}

func TestDecoder_Skip(t *testing.T) {
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

func TestDecoder_Stack(t *testing.T) {
	tests := map[string]struct {
		input  []byte
		want   Header
		depth  int
		offset int64
	}{
		"Root": {[]byte{},
			Header{0, true, LengthIndefinite}, 0, 0},
		"RootAfterValue": {[]byte{0x02, 0x01, 0x15},
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
			var val io.ReadCloser
			for err == nil {
				_, val, err = d.ReadHeader()
				if err == nil && val != nil {
					err = val.Close()
				}
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
