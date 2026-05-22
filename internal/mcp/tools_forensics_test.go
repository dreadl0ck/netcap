/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestExtractIOCsFindsAllKinds exercises every hand-tuned regex
// (url, domain, ipv4, ipv6, email) against a representative payload.
// A regression in any one of the regexes is exactly the bug class this
// catches.
func TestExtractIOCsFindsAllKinds(t *testing.T) {
	payload := `Phishing kit references:
http://malicious.example.com/login
https://192.0.2.5/c2/beacon
contact alice@evil.example and bob@phish.test
fallback host: badguy.evil.example.org
DNS: 2001:db8::1234
`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/extracted-files/download/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(payload))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("extract_iocs_from_file")
	if tool == nil {
		t.Fatal("extract_iocs_from_file not registered")
	}

	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "extract_iocs_from_file",
			Arguments: map[string]any{
				"session_id": "/data/x.pcap",
				"file_path":  "malware.bin",
			},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error result: %s", contentText(res))
	}
	var out map[string]any
	if jErr := json.Unmarshal([]byte(contentText(res)), &out); jErr != nil {
		t.Fatalf("decode: %v", jErr)
	}
	urls, _ := out["urls"].([]any)
	if len(urls) < 2 {
		t.Errorf("urls = %v", urls)
	}
	emails, _ := out["emails"].([]any)
	if len(emails) != 2 {
		t.Errorf("emails = %v", emails)
	}
	ips, _ := out["ips"].([]any)
	// Expect at least 192.0.2.5 (v4) and 2001:db8::1234 (v6).
	if len(ips) < 2 {
		t.Errorf("ips = %v", ips)
	}
	domains, _ := out["domains"].([]any)
	if len(domains) == 0 {
		t.Errorf("domains = %v", domains)
	}
}

// TestGetImageExifNoData: a non-image file produces a graceful empty
// entries list rather than an error. This pins the errors.Is(ErrNoExif)
// special-case branch that's easy to lose in a refactor.
func TestGetImageExifNoData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/extracted-files/download/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not an image"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("get_image_exif")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "get_image_exif",
			Arguments: map[string]any{
				"session_id": "/x.pcap",
				"file_path":  "x",
			},
		},
	})
	if res.IsError {
		t.Fatalf("error result: %s", contentText(res))
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	entries, _ := out["entries"].([]any)
	if len(entries) != 0 {
		t.Errorf("entries = %v", entries)
	}
}
