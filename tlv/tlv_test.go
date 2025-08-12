package tlv

import (
	"fmt"
	"math"
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
