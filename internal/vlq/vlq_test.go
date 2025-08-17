package vlq

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"testing"
)

//region Testing Helpers

// readTestCase represents a single reading test case for type T.
type readTestCase[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64] struct {
	data       []byte // input
	extraBytes int    // number of extra bytes after VLQ
	want       T      // expected output
	wantErr    error  // expected error
}

// testRead asserts that decoding a VLQ using f from tc.data produces the expected results.
func testRead[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](t *testing.T, f func(io.ByteReader) (T, error), tc readTestCase[T]) {
	t.Helper()
	fName := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	r := bytes.NewReader(tc.data)
	got, err := f(r)
	if !errors.Is(err, tc.wantErr) {
		t.Fatalf("%s(%# x) error = %v, wantErr %v", fName, tc.data, err, tc.wantErr)
	}
	if err != nil {
		return
	}
	if got != tc.want {
		t.Errorf("%s(%# x) got = %v, want %v", fName, tc.data, got, tc.want)
	}
	if r.Len() != tc.extraBytes {
		t.Errorf("%s(%# x) extra bytes = %d, want %d", fName, tc.data, r.Len(), tc.extraBytes)
	}
}

// writeTestCase represents a single writing test case for type T.
type writeTestcase[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64] struct {
	value T
	want  []byte
}

// testWrite asserts that writing tc.value as a TLV produces the bytes in tc.want.
func testWrite[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64](t *testing.T, tc writeTestcase[T]) {
	t.Helper()

	l := Size(tc.value)
	if l != len(tc.want) {
		t.Errorf("Size(%d) = %d, want %d", tc.value, l, len(tc.want))
	}
	var buf bytes.Buffer
	buf.Grow(l)
	n, err := Write(&buf, tc.value)
	if err != nil {
		t.Fatalf("Write(%d) error = %v, want nil", tc.value, err)
	}
	if n != len(tc.want) {
		t.Errorf("Write(%d) n = %d, want %d", tc.value, n, len(tc.want))
	}
	if got := buf.Bytes(); !slices.Equal(got, tc.want) {
		t.Errorf("Write(%d) = %# x, want %# x", tc.value, got, tc.want)
	}
}

//endregion

//region Read Tests

func Test_Read(t *testing.T) {
	tests := map[string]readTestCase[uint]{
		"SingleByte":    {[]byte{0x05}, 0, 5, nil},
		"MultiByte":     {[]byte{0x85, 0x01, 0x00}, 1, 641, nil},
		"EOF":           {nil, 0, 0, io.EOF},
		"UnexpectedEOF": {[]byte{0x81, 0x80}, 0, 0, io.ErrUnexpectedEOF},
		"Overflow":      {[]byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 0, 0, errOverflow}, // assumes uint size of 8 bytes (64 bit architecture)
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			testRead(t, Read[uint], tc)
		})
	}
}

func TestRead8(t *testing.T) {
	tests := map[string]readTestCase[uint8]{
		"SingleByte": {[]byte{0x05}, 0, 5, nil},
		"Overflow":   {[]byte{0x85, 0x01, 0x00}, 0, 0, errOverflow},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			testRead(t, Read[uint8], tc)
		})
	}
}

func TestReadMinimal(t *testing.T) {
	tests := map[string]readTestCase[uint]{
		"NonMinimal": {[]byte{0x80, 0x85, 0x01}, 0, 0, errNotMinimal},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			testRead(t, ReadMinimal[uint], tc)
		})
	}
}

//endregion

//region Write Tests

func Test_Write(t *testing.T) {
	tests := []writeTestcase[uint]{
		{0, []byte{0x00}},
		{25, []byte{25}},
		{641, []byte{0x85, 0x01}},
	}
	for _, tc := range tests {
		t.Run(strconv.FormatUint(uint64(tc.value), 10), func(t *testing.T) {
			testWrite(t, tc)
		})
	}
}

func TestWrite8(t *testing.T) {
	tests := []writeTestcase[uint8]{
		{0, []byte{0x00}},
		{200, []byte{0x81, 0x48}},
	}
	for _, tc := range tests {
		t.Run(strconv.FormatUint(uint64(tc.value), 10), func(t *testing.T) {
			testWrite(t, tc)
		})
	}
}

//endregion

func BenchmarkLength(b *testing.B) {
	for b.Loop() {
		Size(uint8(200))
	}
}
