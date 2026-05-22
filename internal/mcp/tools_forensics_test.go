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

// TestExtractIOCsFindsAllKinds drives the tool against a fake webui that
// returns a payload sprinkled with each IOC kind.
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

// TestExtractIOCsKindsFilter narrows extraction to one kind.
func TestExtractIOCsKindsFilter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/extracted-files/download/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("urls https://a.example and emails x@y.example"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL})
	tool := srv.mcpSrv.GetTool("extract_iocs_from_file")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "extract_iocs_from_file",
			Arguments: map[string]any{
				"session_id": "/x.pcap",
				"file_path":  "x",
				"kinds":      "email",
			},
		},
	})
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	if _, hasURLs := out["urls"]; hasURLs {
		t.Errorf("expected no urls key")
	}
	emails, _ := out["emails"].([]any)
	if len(emails) != 1 {
		t.Errorf("emails = %v", emails)
	}
}

// TestParseIOCKindsDefaults: empty/invalid CSV → all kinds.
func TestParseIOCKindsDefaults(t *testing.T) {
	for _, in := range []string{"", "bogus", "foo,bar"} {
		k := parseIOCKinds(in)
		if !(k["url"] && k["domain"] && k["ip"] && k["email"]) {
			t.Errorf("parseIOCKinds(%q) missing defaults: %v", in, k)
		}
	}
	k := parseIOCKinds("url,ip")
	if !(k["url"] && k["ip"]) || k["email"] {
		t.Errorf("subset filter failed: %v", k)
	}
}

// TestGetImageExifNoData returns a graceful empty-list response when the
// file has no EXIF segment (which is the case for plain text).
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

// TestUniqueLimited dedupes and caps.
func TestUniqueLimited(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b", "d", "e"}
	got := uniqueLimited(in, 3)
	if len(got) != 3 {
		t.Errorf("got %v, want 3 items", got)
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("order/value: %v", got)
	}
}
