package netcap

import "testing"

func TestCountRecords(t *testing.T) {
	num := Count("tests/TCP.ncap.gz")
	if num != 3196 {
		t.Fatal("expected 3196 audit records")
	}
}
