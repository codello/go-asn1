// Copyright 2025 Kim Wittenburg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn1

import (
	"testing"
	"time"
)

func ExampleEnumerated() {
	type Option int
	type MyType struct {
		I int    // ASN.1 INTEGER
		J Option // ASN.1 ENUMERATED
	}
}

func TestTime_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Time
		want string
	}{
		"Example":   {time.Date(1985, 11, 06, 21, 06, 21, 0, time.UTC), "1985-11-06T21:06:21Z"},
		"Nanos":     {time.Date(1985, 11, 06, 21, 06, 21, 500000000, time.UTC), "1985-11-06T21:06:21.5Z"},
		"LocalTime": {time.Date(1985, 11, 06, 21, 06, 21, 500000000, time.Local), "1985-11-06T21:06:21.5"},
		"FixedTime": {time.Date(2582, 11, 06, 21, 06, 21, 500000000, time.FixedZone("", 5*3600)), "2582-11-06T21:06:21.5+05:00"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Time(tt.t).String(); got != tt.want {
				t.Errorf("Time.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUTCTime_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Time
		want string
	}{
		"EarlyUTC":       {time.Date(1962, 7, 23, 16, 12, 3, 0, time.UTC), "620723161203Z"},
		"LateUTC":        {time.Date(2048, 7, 23, 8, 12, 0, 0, time.UTC), "480723081200Z"},
		"PositiveOffset": {time.Date(2048, 7, 23, 23, 12, 0, 0, time.FixedZone("", 3*60*60)), "480723231200+0300"},
		"NegativeOffset": {time.Date(2048, 7, 23, 2, 12, 0, 0, time.FixedZone("", -(5*60+30)*60)), "480723021200-0530"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := UTCTime(tt.t).String(); got != tt.want {
				t.Errorf("UTCTime.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGeneralizedTime_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Time
		want string
	}{
		"Example":       {time.Date(1985, 11, 06, 21, 06, 27, 300000000, time.Local), "19851106210627.3"},
		"ExampleUTC":    {time.Date(1985, 11, 06, 21, 06, 27, 300000000, time.UTC), "19851106210627.3Z"},
		"Fractional":    {time.Date(1985, 11, 06, 21, 06, 27, 30000000, time.UTC), "19851106210627.03Z"},
		"ExampleOffset": {time.Date(1985, 11, 06, 21, 06, 27, 300000000, time.FixedZone("", -5*3600)), "19851106210627.3-0500"},
		"Example2":      {time.Date(1985, 11, 06, 21, 06, 00, 456000000, time.Local), "19851106210600.456"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := GeneralizedTime(tt.t).String(); got != tt.want {
				t.Errorf("GeneralizedTime.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDate_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Time
		want string
	}{
		"Simple":    {time.Date(6352, 4, 23, 0, 0, 0, 0, time.UTC), "6352-04-23"},
		"LocalTime": {time.Date(6352, 4, 23, 0, 0, 0, 0, time.Local), "6352-04-23"},
		"WithTime":  {time.Date(6352, 4, 23, 18, 2, 4, 62, time.Local), "6352-04-23"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Date(tt.t).String(); got != tt.want {
				t.Errorf("Date.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTimeOfDay_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Time
		want string
	}{
		"Simple":         {time.Date(0, 0, 0, 15, 12, 8, 0, time.Local), "15:12:08"},
		"IgnoreDate":     {time.Date(1985, 12, 5, 15, 12, 8, 0, time.Local), "15:12:08"},
		"IgnoreLocation": {time.Date(1985, 12, 5, 15, 12, 8, 0, time.UTC), "15:12:08"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := TimeOfDay(tt.t).String(); got != tt.want {
				t.Errorf("TimeOfDay.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDateTime_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Time
		want string
	}{
		"Simple":         {time.Date(1985, 12, 5, 15, 12, 8, 0, time.Local), "1985-12-05T15:12:08"},
		"IgnoreTimeZone": {time.Date(1985, 12, 5, 15, 12, 8, 0, time.UTC), "1985-12-05T15:12:08"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := DateTime(tt.t).String(); got != tt.want {
				t.Errorf("DateTime.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDuration_String(t *testing.T) {
	tests := map[string]struct {
		t    time.Duration
		want string
	}{
		"Zero":       {0, "PT0S"},
		"Hour":       {time.Hour, "PT1H"},
		"Minute":     {time.Minute, "PT1M"},
		"Second":     {time.Second, "PT1S"},
		"Mixed":      {2*time.Hour + 23*time.Minute + 15*time.Second, "PT2H23M15S"},
		"Fractional": {15*time.Second + 13*time.Millisecond, "PT15.013S"},
		"Negative":   {-2*time.Hour - 15*time.Minute - 4*time.Second, "-PT2H15M4S"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Duration(tt.t).String(); got != tt.want {
				t.Errorf("Duration.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestItoaN(t *testing.T) {
	tests := map[string]struct {
		i    int
		n    int
		want string
	}{
		"2-digit":     {23, 2, "23"},
		"2-digit-pad": {7, 2, "07"},
		"4-digit":     {1023, 4, "1023"},
		"4-digit-pad": {18, 4, "0018"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := itoaN(tt.i, tt.n); got != tt.want {
				t.Errorf("ItoaN() = %v, want %v", got, tt.want)
			}
		})
	}
}
