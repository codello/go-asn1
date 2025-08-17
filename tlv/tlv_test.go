package tlv

import (
	"fmt"
	"math"
	"testing"
)

func ExampleCombinedLength() {
	fmt.Println(CombinedLength(42, LengthIndefinite))
	fmt.Println(CombinedLength(math.MaxInt, 2))

	// Output:
	// -1
	// -1
}

func ExampleMinLength() {
	fmt.Println(MinLength(42, LengthIndefinite))

	// Output: 42
}

func TestHeaderSize(t *testing.T) {
	tests := map[string]struct {
		h    Header
		want int
	}{
		"Smallest":     {Header{}, 2},
		"MediumTag":    {Header{50, false, 0}, 3},
		"LargeTag":     {Header{5726, false, 0}, 4},
		"Indefinite":   {Header{0, false, LengthIndefinite}, 2},
		"MediumLength": {Header{0, false, 200}, 3},
		"LargeLength":  {Header{0, false, 256}, 4},
		"HugeLength":   {Header{0, false, 70000}, 5},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := HeaderSize(tc.h)
			if got != tc.want {
				t.Errorf("HeaderSize(%s) = %d, want %d", tc.h, got, tc.want)
			}
		})
	}
}
