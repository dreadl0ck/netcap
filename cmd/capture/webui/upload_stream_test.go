package webui

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestBoundedCaptureUpload(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	for _, tc := range []struct {
		name                        string
		filename                    string
		size                        int
		duplicate, truncate, cancel bool
		ok                          bool
	}{
		{name: "exact limit chunked", filename: "x.pcap", size: 1024, ok: true},
		{name: "over limit chunked", filename: "x.pcap", size: 1025},
		{name: "empty", filename: "x.pcap"},
		{name: "extension", filename: "x.txt", size: 1024},
		{name: "duplicate", filename: "x.pcap", size: 20, duplicate: true},
		{name: "truncated multipart", filename: "x.pcap", size: 20, truncate: true},
		{name: "canceled", filename: "x.pcapng", size: 20, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			part, err := mw.CreateFormFile("file", tc.filename)
			if err != nil {
				t.Fatal(err)
			}
			data := bytes.Repeat([]byte{42}, tc.size)
			part.Write(data)
			if tc.duplicate {
				part, _ = mw.CreateFormFile("file", "other.pcap")
				part.Write(data)
			}
			mw.Close()
			raw := body.Bytes()
			if tc.truncate {
				raw = raw[:len(raw)-8]
			}
			r := httptest.NewRequest(http.MethodPost, "/api/upload", bytes.NewReader(raw))
			r.ContentLength = -1
			r.Header.Set("Content-Type", mw.FormDataContentType())
			if tc.cancel {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			f, header, err := receiveCaptureUpload(httptest.NewRecorder(), r, 1024)
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v, error=%v", tc.ok, err)
			}
			if f != nil {
				got, readErr := io.ReadAll(f)
				info, _ := f.Stat()
				if readErr != nil || !bytes.Equal(got, data) || header.Size != int64(tc.size) || info.Mode().Perm() != 0600 {
					t.Errorf("upload bytes, size or private permissions differ")
				}
				f.Close()
				os.Remove(f.Name())
			}
			entries, err := os.ReadDir(tmp)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary uploads leaked: %v %v", entries, err)
			}
		})
	}
}

func TestCaptureUploadRequestCap(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "x.pcap")
	part.Write([]byte{1})
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/upload", bytes.NewReader(body.Bytes()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Content-Length", "999999999")
	r.ContentLength = 999999999
	f, _, err := receiveCaptureUpload(httptest.NewRecorder(), r, 1024)
	if f != nil {
		f.Close()
		os.Remove(f.Name())
	}
	if err == nil {
		t.Fatal("oversized declared request accepted")
	}
	r = httptest.NewRequest(http.MethodPost, "/api/upload", io.MultiReader(bytes.NewReader(body.Bytes()), bytes.NewReader(make([]byte, uploadFormOverhead+1024))))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.ContentLength = -1
	f, _, err = receiveCaptureUpload(httptest.NewRecorder(), r, 1024)
	if f != nil {
		f.Close()
		os.Remove(f.Name())
	}
	if err == nil {
		t.Fatal("oversized chunked epilogue accepted")
	}
}
