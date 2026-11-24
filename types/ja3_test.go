package types

import "testing"

func TestClientHelloJA3(t *testing.T) {
	// MD5 of 771,4865-4866,0-43-10-11,29-23,0. GREASE is removed,
	// but extension 43 must stay before 10 and the legacy version stays 771.
	const want = "eddfe67bbe8b2ae2540235ce5ff1ae31"
	if got := ClientHelloJA3(771, []int32{0x1a1a, 4865, 4866}, []int32{0, 43, 0x2a2a, 10, 11}, []int32{29, 0x3a3a, 23}, []int32{0}); got != want {
		t.Fatalf("JA3 = %q, want %q", got, want)
	}
	if got := ClientHelloJA3(2, []int32{1}, nil, nil, nil); got != "" {
		t.Fatalf("unexpected JA3 for SSLv2: %s", got)
	}
}
