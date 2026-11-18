package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestArtifactListingCountsAllEntriesAndPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "b"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z", filepath.Join("b", "a"), ".netcap-artifact-pending"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var paths []string
	visit := func(path string, _ os.FileInfo) error { paths = append(paths, path); return nil }
	if err := walkArtifactListing(context.Background(), dir, 4, visit); err != nil || !slices.Equal(paths, []string{filepath.Join("b", "a"), "z"}) {
		t.Fatalf("paths=%v, err=%v", paths, err)
	}
	if err := walkArtifactListing(context.Background(), dir, 3, visit); !errors.Is(err, errArtifactListingLimit) {
		t.Fatalf("expected entry-limit error, got %v", err)
	}
}

func TestExtractedFileInventoryPressure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	request := func(ctx context.Context, status int) {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleExtractedFiles(w, httptest.NewRequest("GET", "/api/extracted-files", nil).WithContext(ctx))
		if w.Code != status {
			t.Fatalf("status=%d want=%d: %.256s", w.Code, status, w.Body.String())
		}
	}
	ctx := context.Background()
	func() {
		for range cap(extractedFileInventorySlots) {
			extractedFileInventorySlots <- struct{}{}
			defer func() { <-extractedFileInventorySlots }()
		}
		request(ctx, 429)
	}()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	request(canceled, 408)
	row := &types.File{Location: "files/artifact", Name: strings.Repeat("x", 1<<20)}
	rows := make([]proto.Message, 33)
	for i := range rows {
		rows[i] = row
	}
	writeTimelineAuditFile(t, dir, "File", types.Type_NC_File, rows)
	request(ctx, 413)
	writeTimelineAuditFile(t, dir, "File", types.Type_NC_File, nil)
	request(ctx, 200)
	deep := filepath.Join(dir, "files", filepath.FromSlash(strings.Repeat("d/", 33)))
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	request(ctx, 413)
	if len(extractedFileInventorySlots) != 0 {
		t.Fatal("inventory leaked a scan slot")
	}
}

func TestExtractedFileInventoryRejectsLinkedPreferredAudit(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0700); err != nil {
		t.Fatal(err)
	}
	writeTimelineAuditFilePlain(t, dir, "File", types.Type_NC_File, nil)
	other := writeTimelineAuditFile(t, t.TempDir(), "File", types.Type_NC_File, nil)
	if err := os.Symlink(other, filepath.Join(dir, "File.ncap.gz")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleExtractedFiles(w, httptest.NewRequest("GET", "/api/extracted-files", nil))
	if w.Code != 403 {
		t.Fatalf("linked preferred audit: status=%d, body=%s", w.Code, w.Body.String())
	}
}

func TestFileOccurrenceCompletenessAndActualCap(t *testing.T) {
	for _, count := range []int{2, 1024, 1025} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "files"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "files", "artifact")
			if err := os.WriteFile(path, []byte("artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			rows := make([]proto.Message, count)
			for i := range rows {
				rows[i] = &types.File{Timestamp: 1700000000000000001 + int64(i), Location: path, Name: "transfer", IsComplete: i > 0, CompletenessReason: "observed transfer", Hashes: &types.FileHashes{SHA256: strings.Repeat("a", 64)}}
			}
			writeTimelineAuditFile(t, dir, "File", types.Type_NC_File, rows)
			s := &Server{outDir: dir}
			w := httptest.NewRecorder()
			s.handleExtractedFiles(w, httptest.NewRequest("GET", "/api/extracted-files", nil))
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			var result struct {
				Files []struct {
					SHA256      string              `json:"sha256"`
					Capped      bool                `json:"occurrencesCapped"`
					Occurrences []map[string]string `json:"occurrences"`
				} `json:"files"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Files) != 1 {
				t.Fatalf("files=%d", len(result.Files))
			}
			file := result.Files[0]
			if file.SHA256 != strings.Repeat("a", 64) || file.Capped != (count > 1024) || len(file.Occurrences) != min(count, 1024) {
				t.Fatalf("count=%d cap=%v occurrences=%d", count, file.Capped, len(file.Occurrences))
			}
			if file.Occurrences[0]["isComplete"] != "false" || file.Occurrences[1]["isComplete"] != "true" || file.Occurrences[0]["timestampNs"] != "1700000000000000001" {
				t.Fatal("transfer qualifications lost")
			}
		})
	}
}
