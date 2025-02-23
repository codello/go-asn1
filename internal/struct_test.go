// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"reflect"
	"testing"
)

func Test_structFields(t *testing.T) {
	type Embedded struct{ A, B int }
	tests := map[string]struct {
		value any
		want  int
	}{
		"Simple": {struct{ A, B int }{}, 2},
		"Ignored": {struct {
			A int
			B int `asn1:"-"`
			C string
		}{}, 2},
		"Embedded": {
			struct {
				X string
				Embedded
			}{}, 3,
		},
		"NonExported": {
			struct {
				a int
				B int
			}{}, 1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := 0
			for range StructFields(reflect.ValueOf(tt.value)) {
				got++
			}
			if got != tt.want {
				t.Errorf("structFields() = %v, want %v", got, tt.want)
			}
		})
	}
}
