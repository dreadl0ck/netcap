package webui

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/dreadl0ck/netcap/types"
)

func TestFlowQueryEvidenceAndUnavailableStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Connection.ncap.gz")
	q := flow.Query{StartNs: 0, EndNs: 60000000000, GroupBy: "srcIP", SortBy: "bytes", Limit: 100}
	if _, err := readFlowQuery(context.Background(), path, q); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing telemetry: %v", err)
	}
	var source bytes.Buffer
	gz := gzip.NewWriter(&source)
	writer := delimited.NewWriter(gz)
	if err := writer.PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		c := &types.Connection{ObservationID: "fixture", CounterSemantics: "tuple-cumulative", SnapshotSequence: uint64(i), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "12345", DstPort: "80", TransportProto: "TCP", TimestampLast: 60000000000, TotalSize64: int64(i) * 300000000, NumPackets64: int64(i) * 10}
		if err := writer.PutProto(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := readFlowQuery(context.Background(), path, q)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(source.Bytes())
	if r.RecordFileSHA256 != hex.EncodeToString(digest[:]) || r.Matched != 1 || r.CollapsedSnapshots != 1 || r.Groups[0].Bytes != 600000000 || r.Groups[0].AverageBitsPerSecond != 80000000 || r.Groups[0].Members[0].Ordinal != 1 {
		t.Fatalf("query evidence: %+v", r)
	}
	if err := os.WriteFile(path, source.Bytes()[:source.Len()-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFlowQuery(context.Background(), path, q); err == nil {
		t.Fatal("truncated telemetry reported as healthy query")
	}
}
