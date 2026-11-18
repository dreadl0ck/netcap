package webui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

func TestStreamEvidenceOrdersByCaptureIdentity(t *testing.T) {
	for _, order := range [][]string{{"stream-z", "stream-a", "stream-m"}, {"stream-m", "stream-a", "stream-z"}} {
		out := t.TempDir()
		for _, id := range order {
			timestamp := map[string]string{"stream-z": "200", "stream-a": "300", "stream-m": "100"}[id]
			dir := filepath.Join(out, "stream-evidence", id)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			manifest := streamutils.StreamEvidenceManifest{Version: 1, FirstPacketNs: timestamp, ConnectionKey: id}
			if id == "stream-m" {
				manifest.Spans = make([]streamutils.StreamEvidenceSpan, 50000)
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		s := &Server{outDir: out}
		w := httptest.NewRecorder()
		s.handleStreamEvidence(w, httptest.NewRequest("GET", "/api/investigation/streams", nil))
		var rows []struct {
			ID           string
			SpanCount    int
			SpansOmitted bool
			Manifest     streamutils.StreamEvidenceManifest
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != 200 {
			t.Fatal(err, w.Body.String())
		}
		if len(rows) != 3 || rows[0].ID != "stream-m" || rows[1].ID != "stream-z" || rows[2].ID != "stream-a" {
			t.Fatalf("directory order leaked into capture ordering: %+v", rows)
		}
		if row := rows[0]; row.SpanCount != 50000 || !row.SpansOmitted || len(row.Manifest.Spans) != 0 || row.Manifest.ConnectionKey != row.ID {
			t.Fatalf("inventory lost span count or metadata: %+v", row)
		}
	}
}
