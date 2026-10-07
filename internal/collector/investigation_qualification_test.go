package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flow"
)

func TestInvestigationPacketToFlowQualification(t *testing.T) {
	input := filepath.Join(t.TempDir(), "investigation.pcap")
	packets, bytes := workerReplayPCAP(t, input, 1)
	t.Setenv("NETCAP_WORKER_REPLAY_CONNECTIONS", "1")
	query := flow.Query{StartNs: math.MinInt64, EndNs: math.MaxInt64, GroupBy: "protocol", SortBy: "bytes", Limit: 10}
	for _, workers := range []int{1, 2, 4, 8} {
		for _, flush := range []int{0, 7} {
			t.Run(fmt.Sprintf("workers=%d/flush=%d", workers, flush), func(t *testing.T) {
				out := t.TempDir()
				workerReplayRun(t, input, out, workers, flush, 1)
				result, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), query)
				if err != nil {
					t.Fatal(err)
				}
				if result.Matched != workerReplayFlows || len(result.Groups) != 1 || result.Groups[0].Key != "TCP" || result.Groups[0].Bytes != int64(bytes) || result.Groups[0].Packets != int64(packets) {
					t.Fatalf("packet/flow evidence differs from fixture ledger: %+v; want bytes=%d packets=%d", result, bytes, packets)
				}
				data, err := os.ReadFile(filepath.Join(out, "capture-manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				var capture evidence.CaptureManifest
				if err := json.Unmarshal(data, &capture); err != nil {
					t.Fatal(err)
				}
				if capture.Status != "done" || capture.IngressPackets != uint64(packets) || capture.AdmittedPackets != uint64(packets) || len(capture.InputSHA256) != 64 || capture.QueueDrops != 0 {
					t.Fatalf("capture provenance differs from fixture: %+v", capture)
				}
			})
		}
	}
	manifest, err := evidence.ArchiveToFile(context.Background(), input, filepath.Join(t.TempDir(), "evidence.zip"), evidence.Selection{BPF: "tcp", MaxPackets: packets + 1})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SourcePackets != uint64(packets) || manifest.Selected != uint64(packets) || len(manifest.SourceSHA256) != 64 || len(manifest.OutputSHA256) != 64 {
		t.Fatalf("packet provenance differs from fixture ledger: %+v", manifest)
	}
}
