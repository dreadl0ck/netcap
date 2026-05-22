/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestCarveStorePutAndGet verifies on-disk + in-memory storage and that
// the SHA-256 reported back matches the content.
func TestCarveStorePutAndGet(t *testing.T) {
	dir := t.TempDir()
	cs := NewCarveStore(dir, 4, time.Hour)
	body := []byte("\xd4\xc3\xb2\xa1fake-pcap-content")
	want := sha256.Sum256(body)

	entry, uri, err := cs.Put("sess1", "host", "http://x/y", body)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.HasPrefix(uri, "netcap://carve/") {
		t.Errorf("uri = %q", uri)
	}
	if entry.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("SHA256 = %q", entry.SHA256)
	}
	if entry.SizeBytes != int64(len(body)) {
		t.Errorf("SizeBytes = %d", entry.SizeBytes)
	}
	got, err := os.ReadFile(entry.Path)
	if err != nil {
		t.Fatalf("read disk: %v", err)
	}
	if string(got) != string(body) {
		t.Error("disk content != bytes")
	}

	// Retrieving by id works.
	id := strings.TrimPrefix(uri, "netcap://carve/")
	if e := cs.Get(id); e == nil || e.SHA256 != entry.SHA256 {
		t.Errorf("Get returned %v", e)
	}
}

// TestCarveStoreEvictsByCount enforces the FIFO cap on entry count.
func TestCarveStoreEvictsByCount(t *testing.T) {
	cs := NewCarveStore(t.TempDir(), 3, time.Hour)
	var paths []string
	for i := 0; i < 5; i++ {
		e, _, err := cs.Put("s", "k", "src", []byte(fmt.Sprintf("body-%d", i)))
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		paths = append(paths, e.Path)
	}
	count, _ := cs.Stats()
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	// The first two on-disk files should have been removed.
	if _, err := os.Stat(paths[0]); !os.IsNotExist(err) {
		t.Errorf("path[0] still on disk: %v", err)
	}
	if _, err := os.Stat(paths[1]); !os.IsNotExist(err) {
		t.Errorf("path[1] still on disk: %v", err)
	}
}

// TestCarveStoreEvictsByAge confirms time-based GC.
func TestCarveStoreEvictsByAge(t *testing.T) {
	cs := NewCarveStore(t.TempDir(), 10, 10*time.Millisecond)
	if _, _, err := cs.Put("s", "k", "src", []byte("ancient")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	// Trigger gc by inserting again.
	if _, _, err := cs.Put("s", "k", "src", []byte("recent")); err != nil {
		t.Fatal(err)
	}
	count, _ := cs.Stats()
	if count != 1 {
		t.Errorf("count = %d, want 1 (older entry should have aged out)", count)
	}
}

// TestCarveHandlerEndToEnd drives the carve_subpcap_for_host tool against
// a fake webui that returns a small PCAP. Verifies the response shape,
// the resource URI, and the on-disk file.
func TestCarveHandlerEndToEnd(t *testing.T) {
	pcapBody := []byte("\xd4\xc3\xb2\xa1pretend pcap bytes ABCDEF")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hosts/download-pcap", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("host") != "10.0.0.1" {
			t.Errorf("unexpected host param: %q", r.URL.Query().Get("host"))
		}
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		_, _ = w.Write(pcapBody)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	carveDir := filepath.Join(t.TempDir(), "carve")
	srv, err := New(Options{BaseURL: ts.URL, CarveDir: carveDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tool := srv.mcpSrv.GetTool("carve_subpcap_for_host")
	if tool == nil {
		t.Fatal("carve_subpcap_for_host not registered")
	}

	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "carve_subpcap_for_host",
			Arguments: map[string]any{
				"session_id": "abcdef0123456789abcdef0123456789", // service-mode hex id
				"host":       "10.0.0.1",
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
	if out["kind"] != "host" {
		t.Errorf("kind = %v", out["kind"])
	}
	if out["size_bytes"].(float64) != float64(len(pcapBody)) {
		t.Errorf("size_bytes = %v", out["size_bytes"])
	}
	wantHash := sha256.Sum256(pcapBody)
	if out["sha256"] != hex.EncodeToString(wantHash[:]) {
		t.Errorf("sha256 = %v", out["sha256"])
	}
	uri, _ := out["resource_uri"].(string)
	if !strings.HasPrefix(uri, "netcap://carve/") {
		t.Errorf("resource_uri = %q", uri)
	}
	filePath, _ := out["file_path"].(string)
	if filePath == "" {
		t.Error("file_path missing")
	} else {
		got, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("read file_path: %v", err)
		}
		if string(got) != string(pcapBody) {
			t.Error("on-disk content != upstream body")
		}
	}

	// Resource read-back path:
	contents, err := srv.handleCarveResource(context.Background(), mcplib.ReadResourceRequest{
		Params: mcplib.ReadResourceParams{URI: uri},
	})
	if err != nil {
		t.Fatalf("handleCarveResource: %v", err)
	}
	if len(contents) != 1 {
		t.Fatalf("contents = %d", len(contents))
	}
	blob, ok := contents[0].(mcplib.BlobResourceContents)
	if !ok {
		t.Fatalf("not blob contents: %T", contents[0])
	}
	if blob.MIMEType != "application/vnd.tcpdump.pcap" {
		t.Errorf("MIME = %q", blob.MIMEType)
	}
	if blob.Blob == "" {
		t.Error("empty blob")
	}
}

// TestCarveHandlerEmptyResponse maps to a clear error.
func TestCarveHandlerEmptyResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hosts/download-pcap", func(w http.ResponseWriter, r *http.Request) {
		// Empty body.
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, _ := New(Options{BaseURL: ts.URL, CarveDir: t.TempDir()})
	tool := srv.mcpSrv.GetTool("carve_subpcap_for_host")
	res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "carve_subpcap_for_host",
			Arguments: map[string]any{"session_id": "abcdef0123456789abcdef0123456789", "host": "10.0.0.1"},
		},
	})
	if !res.IsError {
		t.Errorf("expected error for empty body, got %s", contentText(res))
	}
	if !strings.Contains(contentText(res), "empty response") {
		t.Errorf("error message: %s", contentText(res))
	}
}
