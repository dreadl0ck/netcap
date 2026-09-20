package file

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type savedFileWriter struct {
	netio.AuditRecordWriter
	mu      sync.Mutex
	records []*types.File
}

func (w *savedFileWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, proto.Clone(msg).(*types.File))
	return nil
}

func TestSaveFileConcurrent(t *testing.T) {
	for _, mode := range []string{"duplicates", "different-content", "dedup-disabled"} {
		t.Run(mode, func(t *testing.T) {
			oldConfig, oldDecoderConfig := GetGlobalConfig(), decoderconfig.Instance
			oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
			cfg := GetDefaultConfig()
			cfg.FileExtraction.Advanced.UseMagicDetection = false
			cfg.FileExtraction.Advanced.DeduplicateFiles = mode != "dedup-disabled"
			SetGlobalConfig(cfg)
			decoderconfig.Instance = &decoderconfig.Config{Out: t.TempDir(), FileStorage: "files"}
			w := &savedFileWriter{}
			Decoder.Writer = w
			ResetDedupCache()
			t.Cleanup(func() {
				SetGlobalConfig(oldConfig)
				decoderconfig.Instance = oldDecoderConfig
				Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount
				ResetDedupCache()
			})
			if mode == "duplicates" {
				// A failed save must not reserve the hash or prevent a later retry.
				blocked := filepath.Join(decoderconfig.Instance.Out, "files")
				if err := os.WriteFile(blocked, []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
				err := SaveFileEnhanced(&core.ConversationInfo{Ident: "same-flow"}, "same content", "same-name", nil, []byte("same content"), nil, "", "", 0, "", "", "HTTP")
				if err == nil || GetDedupStats() != (dedupStats{}) {
					t.Fatalf("failed save: err=%v stats=%+v", err, GetDedupStats())
				}
				if err := os.Remove(blocked); err != nil {
					t.Fatal(err)
				}
			}
			const workers = 32
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					body := "same content"
					if mode == "different-content" {
						body = fmt.Sprintf("content %d", i)
					}
					if err := SaveFileEnhanced(&core.ConversationInfo{Ident: "same-flow"}, body, "same-name", nil, []byte(body), nil, "", "", 0, "", "", "HTTP"); err != nil {
						t.Error(err)
					}
				}()
			}
			close(start)
			wg.Wait()
			if len(w.records) != workers {
				t.Fatalf("records = %d", len(w.records))
			}
			paths := make(map[string]bool)
			for _, record := range w.records {
				paths[record.Location] = true
				data, err := os.ReadFile(record.Location)
				if err != nil || string(data) != record.Source {
					t.Fatalf("saved content mismatch: %q, %v", data, err)
				}
			}
			want := workers
			if mode == "duplicates" {
				want = 1
			}
			if len(paths) != want {
				t.Fatalf("paths = %d, want %d", len(paths), want)
			}
			files := 0
			err := filepath.WalkDir(decoderconfig.Instance.Out, func(_ string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					files++
				}
				return err
			})
			if err != nil || files != want {
				t.Fatalf("disk files = %d, want %d: %v", files, want, err)
			}
			stats := GetDedupStats()
			if mode != "dedup-disabled" && (stats.TotalFiles != workers || stats.UniqueFiles != int64(want) || stats.DuplicateFiles != int64(workers-want)) {
				t.Fatalf("stats: %+v", stats)
			}
			if mode == "duplicates" && stats.BytesSaved != (workers-1)*int64(len("same content")) {
				t.Fatalf("bytes saved: %d", stats.BytesSaved)
			}
		})
	}
}
