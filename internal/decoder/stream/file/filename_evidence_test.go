package file

import (
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashFilenamesPreserveExtensionsAndLongSourceEvidence(t *testing.T) {
	old, cfg, writer, count := decoderconfig.Instance, GetGlobalConfig(), Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance = old
		SetGlobalConfig(cfg)
		Decoder.Writer, Decoder.NumRecordsWritten = writer, count
		ResetDedupCache()
	})
	settings := GetDefaultConfig()
	settings.FileExtraction.Advanced.UseMagicDetection = false
	settings.FileExtraction.Advanced.DeduplicateFiles = false
	SetGlobalConfig(settings)
	decoderconfig.Instance = &decoderconfig.Config{Out: t.TempDir(), FileStorage: "files"}
	w := &savedFileWriter{}
	Decoder.Writer = w
	name := strings.Repeat("base64/", 100) + "artifact"
	c := &core.ConversationInfo{Ident: "192.0.2.1:1->192.0.2.2:80", FirstClientPacket: time.Unix(1, 0)}
	for range 2 {
		if err := SaveFileEnhanced(c, "application/octet-stream", name, nil, []byte("fixture bytes"), nil, "", "", 0, "", "server_to_client", "HTTP"); err != nil {
			t.Fatal(err)
		}
	}
	if len(w.records) != 2 || w.records[0].Location == w.records[1].Location {
		t.Fatal("distinct extraction events collided")
	}
	for _, r := range w.records {
		if r.Name != name {
			t.Fatal("original source filename changed")
		}
		base := filepath.Base(r.Location)
		if len(base) > 100 || strings.Contains(base, "...") || filepath.Ext(base) != ".bin" {
			t.Fatal("unsafe/truncated filename", base)
		}
		info, err := os.Stat(r.Location)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal(info, err)
		}
	}
}

func TestMIMEPathCannotEscapeStorage(t *testing.T) {
	for _, value := range []string{"../escape", "application/../../escape", "/tmp/escape", "text/..", "text/.", ""} {
		if safeMIMEPath(value) != "application/octet-stream" {
			t.Fatal("unsafe MIME path accepted", value)
		}
	}
	if safeMIMEPath("text/plain; charset=utf-8") != "text/plain" {
		t.Fatal("valid MIME parameters not normalized")
	}
}
