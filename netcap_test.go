package netcap

import "testing"

func TestCountRecords(t *testing.T) {
	num, errCount := Count("tests/testdata/TCP.ncap.gz")
	if errCount != nil {
		t.Fatal(errCount)
	}
	if num != 3196 {
		t.Fatal("expected 3196 audit records")
	}
}
