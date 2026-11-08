package webui

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

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
