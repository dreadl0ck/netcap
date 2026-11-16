package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaptureUploadAdmission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.pcap")
	data := bytes.Repeat([]byte{42}, 128<<10)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		reader, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		part, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		got, err := io.ReadAll(part)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("upload mismatch: %v", err)
		}
		io.WriteString(w, `{"success":true}`)
	}))
	defer ts.Close()
	c := NewNetcapClient(ts.URL)
	if _, err := c.UploadPCAPContext(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty.pcap", "bad.txt"} {
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.UploadPCAP(p); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if f, _, err := openCaptureUpload(path, int64(len(data)-1)); err == nil {
		f.Close()
		t.Fatal("accepted capture exceeding admission limit")
	}
	if _, err := c.UploadPCAP(dir + ".pcap"); err == nil {
		t.Fatal("accepted missing file")
	}
	if requests != 1 {
		t.Fatalf("rejected sources reached backend: %d requests", requests)
	}
}

func TestCaptureUploadEarlyRejectionAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, make([]byte, 2<<20), 0600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer ts.Close()
	c := NewNetcapClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.UploadPCAPContext(ctx, path); err == nil {
		t.Fatal("early rejection succeeded")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := c.UploadPCAPContext(canceled, path); err == nil {
		t.Fatal("canceled upload succeeded")
	}
}
