package software

import (
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestBundledParserPrefersEdgeAndPreservesWindowsVersion(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"
	r := ParseUserAgent(ua)
	if r == nil || r.Vendor != "Edge" || r.Version != "18.18362" || !strings.Contains(r.OS, "Windows 10") {
		t.Fatalf("UA evidence: %+v", r)
	}
}

// The try demo's Brazil malspam capture showed an empty Software row: uap-go
// names WinHttp "Other" with device "Spider", the row was written without a
// product, and "Win32" became Windows 95. Indy Library was dropped entirely.
func TestScriptedClientsAreNamedFromTheirCompatibleToken(t *testing.T) {
	for ua, want := range map[string][3]string{
		"Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)":                {"WinHttp.WinHttpRequest", "5", ""},
		"Mozilla/3.0 (compatible; Indy Library)":                                   {"Indy Library", "", ""},
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)":                       {"IE", "6.0", "Windows XP"},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": {"Googlebot", "2.1", ""},
		"Mozilla/5.0": {"", "", ""},
	} {
		r := ParseUserAgent(ua)
		if r == nil || r.Vendor != want[0] || r.Version != want[1] || r.OS != want[2] {
			t.Errorf("%s: %+v", ua, r)
		}
	}
	if r := ParseUserAgent("Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)"); r == nil || r.OS != "Windows 95" {
		t.Fatalf("real Windows 95 lost: %+v", r)
	}
}

func TestHTTPSoftwareNeverHasAnEmptyProduct(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)": "WinHttp.WinHttpRequest",
		"Mozilla/3.0 (compatible; Indy Library)":                    "Indy Library",
		"Mozilla/5.0":                                               "",
	} {
		var products []string
		for _, s := range WhatSoftwareHTTP("flow", &types.HTTP{SrcIP: "10.0.0.1", DstIP: "192.0.2.1", Method: "GET", UserAgent: ua}) {
			if s.SourceName == "UserAgent" {
				products = append(products, s.Product)
			}
		}
		if want == "" && len(products) != 0 || want != "" && (len(products) != 1 || products[0] != want) {
			t.Errorf("%s: %q", ua, products)
		}
	}
}
