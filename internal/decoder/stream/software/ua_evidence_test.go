package software

import (
	"strings"
	"testing"
)

func TestBundledParserPrefersEdgeAndPreservesWindowsVersion(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"
	r := ParseUserAgent(ua)
	if r == nil || r.Vendor != "Edge" || r.Version != "18.18362" || !strings.Contains(r.OS, "Windows 10") {
		t.Fatalf("UA evidence: %+v", r)
	}
}
