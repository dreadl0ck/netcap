package utils

import (
	"testing"
	"time"
)

func TestParseTimestampUTC(t *testing.T) {
	for _, tc := range []struct {
		input          string
		seconds, nanos int64
	}{
		{"1600000000", 1600000000, 0}, {"1600000000.5", 1600000000, 500000000},
		{"1600000000.123456789", 1600000000, 123456789}, {"-5.5", -5, -500000000},
		{"-0.5", 0, -500000000}, {"0.000001", 0, 1000},
	} {
		got, err := ParseTimestampUTC(tc.input)
		if want := time.Unix(tc.seconds, tc.nanos).UTC().String(); err != nil || got != want {
			t.Errorf("%s: %s %v; want %s", tc.input, got, err, want)
		}
	}
	for _, value := range []string{"", "garbage", "1.", "1.-5", "1.1234567890", "1.2.3", "9223372036854775807", "-9223372036854775808"} {
		if _, err := ParseTimestampUTC(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
