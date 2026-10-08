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
	query.GroupBy = "ingressEgress"
	report, err = ReadReport(context.Background(), path, query)
	if err != nil || len(report.Groups) != 1 || report.Groups[0].Key != "unavailable/unavailable" {
		t.Fatalf("missing interfaces became interface zero: %+v, %v", report, err)
	}
	zero := uint64(0)
	query.Egress = &zero
	report, err = ReadReport(context.Background(), path, query)
	if err != nil || report.Matched != 0 {
		t.Fatalf("interface-zero filter included unavailable telemetry: %+v, %v", report, err)
	}
	query.Egress = nil
	query.NextHop = "not-an-address"
	if _, err := ReadReport(context.Background(), path, query); err == nil {
		t.Fatal("invalid next hop silently returned a clean negative")
	}
	query.NextHop = ""
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

func TestExportedPrefixMetadata(t *testing.T) {
	zero, v4, v6, invalid := uint64(0), uint64(24), uint64(48), uint64(129)
	for _, tc := range []struct {
		ip     string
		length *uint64
		want   string
	}{
		{"192.0.2.17", &v4, "192.0.2.0/24"},
		{"2001:db8:1234:abcd::17", &v6, "2001:db8:1234::/48"},
		{"192.0.2.17", &zero, "0.0.0.0/0"},
		{"192.0.2.17", nil, "unavailable"},
		{"192.0.2.17", &v6, "unavailable"},
		{"2001:db8::17", &invalid, "unavailable"},
		{"", &zero, "unavailable"},
	} {
		if got := exportedPrefix(tc.ip, tc.length); got != tc.want {
			t.Fatalf("prefix(%s,%v)=%s want %s", tc.ip, tc.length, got, tc.want)
		}
	}
}
