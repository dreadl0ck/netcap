package flowexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestExportReportScopeCountsAndHealth(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRecorder(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope("192.0.2.10:50000")
	template := shorts(256, 4, 8, 4, 12, 4, 1, 4, 2, 4)
	if err := r.Observe(nf9(0, set(0, template)), env); err != nil {
		t.Fatal(err)
	}
	if err := r.Observe(nf9(1, set(256, words(0xc0000201, 0xc6336401, 600000000, 123))), env); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	id := uint32(7)
	query := Query{StartNs: env.ReceivedNs, EndNs: env.ReceivedNs, TimeBasis: "receive", Exporter: env.Exporter, Format: "netflow-v9", Domain: &id, GroupBy: "srcIP", Limit: 100}
	path := filepath.Join(dir, "FlowExports.jsonl")
	report, err := ReadReport(context.Background(), path, query)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if report.Matched != 1 || report.Groups[0].Bytes != 600000000 || report.Groups[0].Packets != 123 || report.Groups[0].Key != "192.0.2.1" || report.SourceSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("report: %+v", report)
	}
	query.TimeBasis = "flow"
	report, err = ReadReport(context.Background(), path, query)
	if err != nil {
		t.Fatal(err)
	}
	if report.Matched != 0 || report.Excluded != 1 {
		t.Fatal("receive timestamp fabricated as flow time")
	}
	query.Format = "misspelled"
	if _, err := ReadReport(context.Background(), path, query); err == nil {
		t.Fatal("unknown format silently produced empty report")
	}
}
