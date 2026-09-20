//go:build !ja4plus

package ja4plusadapter

import "testing"

func TestDisabled(t *testing.T) {
	if Enabled {
		t.Fatal("JA4+ must be disabled without the ja4plus build tag")
	}
	if got := ComputeJA4S(&ServerHelloData{}); got != "" {
		t.Fatalf("disabled JA4+ returned %q", got)
	}
}
