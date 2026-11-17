package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type sourceFileWriter struct {
	netio.AuditRecordWriter
	records []*types.File
}

func (w *sourceFileWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.File))
	return nil
}

func captureExtractedHTTP(t *testing.T, data core.DataFragments, source bool) ([]*types.HTTP, []*types.File) {
	t.Helper()
	previous, oldConfig := decoderconfig.Instance, file.GetGlobalConfig()
	writer, count, fileWriter, fileCount := Decoder.Writer, Decoder.NumRecordsWritten, file.Decoder.Writer, file.Decoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance = previous
		file.SetGlobalConfig(oldConfig)
		Decoder.Writer, Decoder.NumRecordsWritten = writer, count
		file.Decoder.Writer, file.Decoder.NumRecordsWritten = fileWriter, fileCount
		file.ResetDedupCache()
	})
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance.Out = t.TempDir()
	decoderconfig.Instance.FileStorage = "files"
	decoderconfig.Instance.IncludePayloads = false
	decoderconfig.Instance.WriteIncomplete = true
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Advanced.UseMagicDetection = false
	file.SetGlobalConfig(cfg)
	w, fw := &httpEvidenceWriter{}, &sourceFileWriter{}
	Decoder.Writer = w
	file.Decoder.Writer = fw
	c := &core.ConversationInfo{Ident: "fixture", CommunityID: "1:fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 80, Data: data}
	if source {
		var client, server core.SliceSource
		for _, fragment := range data {
			if core.FromServer(fragment) {
				server = append(server, fragment)
			} else {
				client = append(client, fragment)
			}
		}
		c.Data = nil
		c.ClientSource, c.ServerSource = client, server
		c.Source = core.MergedSource{Client: client, Server: server}
		c.StateBudget, _ = core.NewStateBudget(262144, nil)
		c.LoadData = func() error { t.Fatal("extraction unexpectedly materialized the conversation"); return nil }
	}
	(&httpReader{conversation: c}).Decode()
	if c.FragmentError != nil {
		t.Fatal(c.FragmentError)
	}
	if source && c.StateBudget.Health().RetainedBytes != 0 {
		t.Fatal("source budget leaked", c.StateBudget.Health())
	}
	for _, record := range fw.records {
		got, err := os.ReadFile(record.Location)
		if err != nil {
			t.Fatal(err)
		}
		if file.ComputeHashes(got).SHA256 != record.Hashes.SHA256 {
			t.Fatal("file evidence hash mismatch")
		}
		record.Location = ""
	}
	entries, err := os.ReadDir(filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("scratch files survived extraction", entries)
	}
	return w.records, fw.records
}

func TestHTTPSourceExtractionPreservesRecordsAndBodies(t *testing.T) {
	for _, kind := range []string{"identity", "gzip", "gzip-truncated", "truncated", "chunked-upload", "multipart-upload", "json-upload"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte(strings.Repeat("artifact fixture\n", 5000))
			wire := body
			encoding := ""
			if kind == "gzip" || kind == "gzip-truncated" {
				var output bytes.Buffer
				writer := gzip.NewWriter(&output)
				_, _ = writer.Write(body)
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				wire = output.Bytes()
				if kind == "gzip-truncated" {
					wire = wire[:len(wire)-1]
				}
				encoding = "Content-Encoding: gzip\r\n"
			}
			length := len(wire)
			if kind == "truncated" {
				length += 100
			}
			request := "GET /file.txt HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
			if kind == "chunked-upload" {
				request = "POST /upload.bin HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\nGET /file.txt HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
			}
			if kind == "multipart-upload" {
				multipart := "--fixture\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"fixture.bin\"\r\n\r\n" + strings.Repeat("fixture bytes\n", 240000) + "\r\n--fixture\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\nafter-file\r\n--fixture--\r\n"
				request = fmt.Sprintf("POST /upload?label=query HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: %d\r\n\r\n%sGET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n", len(multipart), multipart)
			}
			if kind == "json-upload" {
				const payload = `{"label":"from-body","count":1,"nested":{"label":"ignored"}}`
				request = fmt.Sprintf("POST /upload?label=query HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/vnd.fixture+json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
			}
			response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n%sContent-Length: %d\r\n\r\n", encoding, length))
			response = append(response, wire...)
			data := core.DataFragments{}
			if kind == "multipart-upload" {
				response = append([]byte("HTTP/1.1 204 No Content\r\n\r\n"), response...)
			}
			for fragment := range slices.Chunk([]byte(request), 16<<10) {
				data = append(data, wireFragment(0, fragment, 1))
			}
			data = append(data, wireFragment(1, response, 2))
			wantHTTP, wantFiles := captureExtractedHTTP(t, data, false)
			gotHTTP, gotFiles := captureExtractedHTTP(t, data, true)
			if !reflect.DeepEqual(gotHTTP, wantHTTP) {
				t.Fatalf("HTTP observations changed:\ngot %v\nwant %v", gotHTTP, wantHTTP)
			}
			if !reflect.DeepEqual(gotFiles, wantFiles) {
				t.Fatalf("file observations changed:\ngot %v\nwant %v", gotFiles, wantFiles)
			}
			if kind == "multipart-upload" && (len(gotHTTP) != 2 || len(gotFiles) != 2 || !strings.Contains(fmt.Sprint(gotHTTP[0].Parameters), "after-file")) {
				t.Fatalf("multipart fields, file, or next message lost: %v / %d", gotHTTP, len(gotFiles))
			}
			if kind == "json-upload" && (len(gotHTTP) != 1 || len(gotFiles) != 2 || !strings.Contains(fmt.Sprint(gotHTTP[0].Parameters), "from-body")) {
				t.Fatalf("JSON form fields or files lost: %v / %d", gotHTTP, len(gotFiles))
			}
		})
	}
}
