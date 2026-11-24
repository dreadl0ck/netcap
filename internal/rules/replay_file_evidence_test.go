package rules

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func replayArtifact(at int64, n int) *types.File {
	return &types.File{
		Timestamp: at, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Length: 42, IsComplete: true,
		Hashes:      &types.FileHashes{SHA256: fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "test artifact %d", n)))},
		CommunityID: "1:fixture", Location: "/private/capture-path", Source: "HTTP GET /file?private-query",
	}
}

func replayArtifactRule() *Rule {
	return &Rule{Name: "Artifact rule", Type: "File", Expression: "IsComplete", Severity: "high", Enabled: true}
}

func TestReplayFileFindingRetainsDistinctMatches(t *testing.T) {
	writer := new(MockAlertWriter)
	replay, err := NewAuditReplay(&Config{Rules: []*Rule{replayArtifactRule()}}, writer)
	if err != nil {
		t.Fatal(err)
	}
	const start = int64(time.Hour)
	for i, id := range []int{1, 2, 2, 3} {
		file := replayArtifact(start+int64(i)*int64(time.Second), id)
		if i == 2 {
			file.Hashes.SHA256 = strings.ToUpper(file.Hashes.SHA256)
		}
		if n, err := replay.Evaluate(file); n != 0 || err != nil {
			t.Fatalf("match %d: wrote %d, err %v", i, n, err)
		}
	}
	if n, err := replay.Evaluate(replayArtifact(start+int64(5*time.Minute), 4)); n != 1 || err != nil {
		t.Fatalf("next window: wrote %d, err %v", n, err)
	}
	row := writer.alerts[0]
	if row.Count != 4 || row.FirstSeen != start || row.LastSeen != start+int64(3*time.Second) || len(row.Examples) != 3 {
		t.Fatalf("unexpected file finding: %+v", row)
	}
	if row.MatchedRecordSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(row.MatchedRecord))) {
		t.Fatal("first record provenance changed")
	}
	for i, raw := range row.Examples {
		var example fileMatchExample
		if err := json.Unmarshal([]byte(raw), &example); err != nil || example.SHA256 != replayArtifact(0, i+1).Hashes.SHA256 || example.CommunityID != "1:fixture" {
			t.Fatalf("wrong example %d: %s (%v)", i, raw, err)
		}
		if strings.Contains(raw, "private-") {
			t.Fatal("example includes a path or query")
		}
	}
	if n, err := replay.Finalize(); n != 1 || err != nil || len(writer.alerts) != 2 {
		t.Fatalf("EOF: wrote %d, err %v", n, err)
	}
	if n, err := replay.Finalize(); n != 0 || err != nil {
		t.Fatalf("repeated EOF: wrote %d, err %v", n, err)
	}
}

func TestReplayFileFindingsBoundExamplesAndRetryFailedWrite(t *testing.T) {
	failure := errors.New("test writer failure")
	fail := true
	var alerts []*types.Alert
	writer := alertWriterFunc(func(a *types.Alert) error {
		if fail {
			return failure
		}
		alerts = append(alerts, a)
		return nil
	})
	replay, err := NewAuditReplay(&Config{Rules: []*Rule{replayArtifactRule()}}, writer)
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxFileMatchExamples + 3 {
		if _, err := replay.Evaluate(replayArtifact(int64(i+1), i)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := replay.Finalize(); n != 0 || !errors.Is(err, failure) {
		t.Fatalf("failed write: %d, %v", n, err)
	}
	fail = false
	if n, err := replay.Finalize(); n != 1 || err != nil || len(alerts) != 1 {
		t.Fatalf("retry write: %d, %v", n, err)
	}
	got := alerts[0]
	if len(got.Examples) != maxFileMatchExamples+1 || got.Count != maxFileMatchExamples+3 || !strings.Contains(got.Examples[maxFileMatchExamples], `"omittedMatches":3`) {
		t.Fatalf("unexpected evidence limit: count=%d examples=%d", got.Count, len(got.Examples))
	}
}

func TestReplayFileEvidenceLeavesExplicitDedupeImmediate(t *testing.T) {
	rule := replayArtifactRule()
	rule.DedupeBy = []string{"Hashes.SHA256"}
	writer := new(MockAlertWriter)
	replay, err := NewAuditReplay(&Config{Rules: []*Rule{rule}}, writer)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := replay.Evaluate(replayArtifact(1, 1)); n != 1 || err != nil {
		t.Fatalf("explicit policy: %d, %v", n, err)
	}
	if n, err := replay.Evaluate(replayArtifact(2, 1)); n != 0 || err != nil {
		t.Fatalf("duplicate: %d, %v", n, err)
	}
	if n, err := replay.Finalize(); n != 0 || err != nil || len(writer.alerts) != 1 {
		t.Fatalf("EOF: %d, %v", n, err)
	}
}

func TestReplayFileEvidenceFlushesAtCapacityWithoutMixingPairs(t *testing.T) {
	writer := new(MockAlertWriter)
	replay, err := NewAuditReplay(&Config{Rules: []*Rule{replayArtifactRule()}}, writer)
	if err != nil {
		t.Fatal(err)
	}
	replay.engine.SetRateLimit(maxPendingFileFindings + 2)
	for i := range maxPendingFileFindings + 1 {
		f := replayArtifact(int64(i+1), i)
		f.DstIP = fmt.Sprintf("2001:db8::%x", i+1)
		if _, err := replay.Evaluate(f); err != nil {
			t.Fatal(err)
		}
	}
	if len(writer.alerts) != 1 || writer.alerts[0].DstIP != "2001:db8::1" || !strings.Contains(writer.alerts[0].Examples[1], `"flushedEarly":true`) {
		t.Fatal("expected the oldest finding to flush at capacity")
	}
	if n, err := replay.Finalize(); n != maxPendingFileFindings || err != nil {
		t.Fatalf("EOF: %d, %v", n, err)
	}
	if len(writer.alerts) != maxPendingFileFindings+1 || len(writer.alerts[1].Examples) != 0 {
		t.Fatal("file findings were lost or evidence leaked into a different endpoint pair")
	}
}
