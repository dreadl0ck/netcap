//go:build ja4plus

package ja4plusadapter

import "testing"

func TestEnabled(t *testing.T) {
	if !Enabled {
		t.Fatal("JA4+ must be enabled with the ja4plus build tag")
	}
	if got := ComputeJA4S(&ServerHelloData{Version: 0x0303, CipherSuite: 0x1301}); got == "" {
		t.Fatal("enabled JA4+ returned an empty fingerprint")
	}
}
