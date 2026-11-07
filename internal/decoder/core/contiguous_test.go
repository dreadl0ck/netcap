package core

import "testing"

func TestContiguousProbeCannotBridgeKnownOrUnknownLoss(t *testing.T) {
	for _, skip := range []int{0, 5, -1} {
		fragments := DataFragments{&StreamData{RawData: []byte("SSH-")}, &StreamData{SkippedBytes: skip}, &StreamData{RawData: []byte("2.0-owned\r\n")}}
		want := "SSH-"
		if skip == 0 {
			want = "SSH-2.0-owned\r\n"
		}
		if got := string(fragments.ContiguousBytes()); got != want {
			t.Fatalf("skip=%d: %q", skip, got)
		}
	}
	leading := DataFragments{nil, &StreamData{SkippedBytes: -1}, &StreamData{RawData: []byte("SSH-2.0-owned\r\n"), SkippedBytes: 5}}
	if got := string(leading.ContiguousBytes()); got != "SSH-2.0-owned\r\n" {
		t.Fatal(got)
	}
}

func TestContiguousProbeCannotBridgeLocalRetentionLoss(t *testing.T) {
	fragments := DataFragments{&StreamData{RawData: []byte("SSH-")}, &StreamData{DiscardedBytes: 2, DiscardReason: "tcp-retained-payload-budget"}, &StreamData{RawData: []byte("2.0-owned\r\n")}}
	if got := string(fragments.ContiguousBytes()); got != "SSH-" {
		t.Fatalf("local omission completed a fabricated greeting: %q", got)
	}
}
