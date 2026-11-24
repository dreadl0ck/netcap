package durable

import "testing"

func TestBarrier(t *testing.T) {
	if err := Barrier(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := Barrier("/nonexistent-netcap-dir"); err == nil && hasBarrier {
		t.Fatal("missing directory accepted")
	}
}
