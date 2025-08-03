// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn1

import (
	"fmt"
)

func ExampleTag_String() {
	t1 := ClassApplication | 17
	t2 := ClassContextSpecific | 8
	t3 := ClassUniversal | 2
	fmt.Println(t1.String())
	fmt.Println(t2.String())
	fmt.Println(t3.String())
	// Output:
	// [APPLICATION 17]
	// [8]
	// [UNIVERSAL 2]
}

func ExampleExtensible() {
	type MyType struct {
		Str string
		Extensible

		private int    // ok, unexported field
		Ignored string `asn1:"-"` // ok, ignored
		// Public int // not ok, cannot appear after Extensible
	}
}
