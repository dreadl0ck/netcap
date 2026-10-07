package file

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func encodedFixture(t *testing.T, body []byte, kind string) []byte {
	t.Helper()
	var output bytes.Buffer
	var writer io.WriteCloser
	switch kind {
	case "gzip":
		writer = gzip.NewWriter(&output)
	case "zlib":
		writer = zlib.NewWriter(&output)
	case "raw-deflate":
		var err error
		writer, err = flate.NewWriter(&output, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestContentHashQualifiedDecoding(t *testing.T) {
	body := make([]byte, 256)
	for i := range body {
		body[i] = byte(i)
	}
	hash := sha256.Sum256(body)
	for _, kind := range []string{"gzip", "zlib", "raw-deflate"} {
		t.Run(kind, func(t *testing.T) {
			encoding := "deflate"
			if kind == "gzip" {
				encoding = "gzip"
			}
			info, err := ComputeContentHashWithLimit(encodedFixture(t, body, kind), []string{encoding}, 1024)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(info.DecodedContent, body) || info.Hash != hex.EncodeToString(hash[:]) || !info.WasCompressed || info.CompressionType != encoding {
				t.Fatalf("decoded evidence changed: %+v", info)
			}
		})
	}
	gz := encodedFixture(t, body, "gzip")
	stacked := []byte(base64.StdEncoding.EncodeToString(gz))
	info, err := ComputeContentHashWithLimit(stacked, []string{"gzip", "base64"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info.DecodedContent, body) {
		t.Fatal("stacked encodings decoded in application order")
	}
}

func TestContentHashFailuresRetainWireEvidence(t *testing.T) {
	body := []byte(strings.Repeat("fixture", 100))
	gz := encodedFixture(t, body, "gzip")
	for _, tc := range []struct {
		name     string
		body     []byte
		encoding []string
		limit    int64
	}{
		{"truncated", gz[:len(gz)-1], []string{"gzip"}, 1024},
		{"invalid-base64", []byte("%%%"), []string{"base64"}, 1024},
		{"unsupported", body, []string{"unknown"}, 1024},
		{"expansion-limit", gz, []string{"gzip"}, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ComputeContentHashWithLimit(tc.body, tc.encoding, tc.limit)
			if err == nil {
				t.Fatal("decoding failure reported as success")
			}
			hash := sha256.Sum256(tc.body)
			if !bytes.Equal(info.DecodedContent, tc.body) || info.Hash != hex.EncodeToString(hash[:]) || info.WasCompressed {
				t.Fatal("fallback lost or mislabelled original evidence")
			}
		})
	}
}

func TestExtractedFileCompletenessTracksErrorsAndStreamLoss(t *testing.T) {
	oldConfig, oldDecoderConfig := GetGlobalConfig(), decoderconfig.Instance
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	cfg := GetDefaultConfig()
	cfg.FileExtraction.Advanced.UseMagicDetection = false
	cfg.FileExtraction.Advanced.DeduplicateFiles = false
	SetGlobalConfig(cfg)
	decoderconfig.Instance = &decoderconfig.Config{Out: t.TempDir(), FileStorage: "files"}
	w := &savedFileWriter{}
	Decoder.Writer = w
	t.Cleanup(func() {
		SetGlobalConfig(oldConfig)
		decoderconfig.Instance = oldDecoderConfig
		Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount
		ResetDedupCache()
	})
	for _, tc := range []struct {
		name     string
		err      error
		encoding []string
		gap      int
		want     string
	}{
		{"complete", nil, nil, 0, "no-reported-loss"},
		{"extraction", errors.New("fixture truncation"), nil, 0, "extraction-error"},
		{"encoding", nil, []string{"gzip"}, 0, "content-decoding-error"},
		{"stream-gap", nil, nil, 42, "unattributed-stream-gap"},
		{"initial-loss", nil, nil, -1, "unknown-initial-stream-loss"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conv := &core.ConversationInfo{Ident: tc.name, FirstClientPacket: time.Unix(1, 2), ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 12345, ServerPort: 80, ClientData: core.DataFragments{&core.StreamData{SkippedBytes: tc.gap}}}
			if err := SaveFileEnhanced(conv, "fixture", tc.name, tc.err, []byte("fixture bytes"), tc.encoding, "", "", 0, "", "server_to_client", "HTTP"); err != nil {
				t.Fatal(err)
			}
			record := w.records[len(w.records)-1]
			if record.CompletenessReason != tc.want || record.IsComplete != (tc.name == "complete") || record.StreamInitialLossUnknown != (tc.gap < 0) {
				t.Fatalf("incorrect completeness: %s", record)
			}
			if tc.gap > 0 && (record.StreamMissingBytes != int64(tc.gap) || record.MissingBytes != 0) {
				t.Fatalf("stream loss falsely attributed to artifact: %s", record)
			}
			data, err := os.ReadFile(record.Location)
			if err != nil || string(data) != "fixture bytes" {
				t.Fatalf("wire fallback changed: %q, %v", data, err)
			}
		})
	}
}
