package tlv

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

func TestBufferedReader(t *testing.T) {
	limits := []int{-1, 0, 1, 10, 20, 64, 1024}
	input := strings.Repeat("abc", 1024)

	for _, limit := range limits {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			r := new(bufferedReader)
			r.Reset(strings.NewReader(input))
			if err := iotest.TestReader(r, []byte(input)); err != nil {
				t.Errorf("Read() returned an unexpected error: %s", err)
			}
		})
	}
}

func TestBufferedReader_Limit(t *testing.T) {
	input := strings.Repeat("abc", 1024)

	for _, limit := range []int{0, 1, 10, 20, 64, 1024} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			sr := strings.NewReader(input)
			r := new(bufferedReader)
			r.Reset(sr)
			r.SetLimit(limit)
			_, err := r.ReadByte()
			if err != nil {
				t.Errorf("ReadByte() returned an unexpected error: %s", err)
			}
			if r.Buffered() > max(limit-1, 0) {
				t.Errorf("r.Buffered() = %d, expected < %d", r.Buffered(), limit)
			}
			if len(input)-sr.Len() != r.Buffered()+1 {
				t.Errorf("r read %d bytes, expected %d", len(input)-sr.Len(), r.Buffered())
			}
		})
	}
}

func TestBufferedReader_Discard(t *testing.T) {
	input := strings.Repeat("abc", 1024)
	t.Run("Seeker", func(t *testing.T) {
		sr := strings.NewReader(input)
		r := new(bufferedReader)
		r.Reset(sr)
		n, err := r.Discard(100)
		if err != nil {
			t.Errorf("r.Discard(100) returned an unexpected error: %s", err)
		}
		if n != 100 {
			t.Errorf("r.Discard(100) = %d, expected %d", n, 100)
		}
	})
	t.Run("DiscardMore", func(t *testing.T) {
		sr := strings.NewReader(input)
		r := new(bufferedReader)
		r.Reset(sr)
		n, err := r.Discard(len(input) + 5)
		if err != io.EOF {
			t.Errorf("r.Discard(%d) returned an unexpected error: %s, want %s", n, err, io.EOF)
		}
		if n != len(input) {
			t.Errorf("r.Discard(%d) = %d, expected %d", len(input)+5, n, len(input))
		}
	})
}
