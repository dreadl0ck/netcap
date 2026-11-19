package collector

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func TestDownloadFastOriginal(t *testing.T) {
	const inputSHA256 = "a9d08b46f0ffafe6671407910184aa521db200568da3e844d92636c0feab0588"
	path := os.Getenv("NETCAP_DOWNLOAD_FAST")
	if path == "" {
		t.Skip("set NETCAP_DOWNLOAD_FAST to the pinned public capture")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 90036941))
	f.Close()
	if err != nil || n != 90036940 || fmt.Sprintf("%x", h.Sum(nil)) != inputSHA256 {
		t.Fatal("original capture mismatch", n, err)
	}
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP,IPP"
	cfg.DecoderConfig.MaxAggregateStateBytes = 1 << 20
	cfg.DecoderConfig.MaxRetainedTCPStateBytes = 256 << 10
	cfg.DecoderConfig.MaxRetainedTCPBytes = 128 << 10
	if err := New(cfg).CollectPcapNG(path); err != nil {
		t.Fatal(err)
	}
	m := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if m.Status != "done" || m.InputSHA256 != inputSHA256 || m.AdmittedPackets != 89942 || m.QueueDrops != 0 {
		t.Fatalf("unexpected manifest: status=%s input=%s admitted=%d drops=%d", m.Status, m.InputSHA256, m.AdmittedPackets, m.QueueDrops)
	}
	stage, _, err := evidence.ReadAuditStage(out, m.RunID, "HTTP", m.AuditStagesGeneration)
	if err != nil || stage.State != "sealed" || stage.Coverage != "complete" || stage.Records != 1 {
		t.Fatalf("unexpected HTTP audit stage: %+v, %v", stage, err)
	}
	rows := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
	if len(rows) != 1 || rows[0].Method != "GET" || rows[0].StatusCode != 200 {
		t.Fatal("unexpected HTTP replay", rows)
	}
	row := rows[0]
	if row.ResContentLength != math.MaxInt32 || !slices.Contains(row.ParseQualifications, "response-content-length-exceeds-int32") || row.ReassemblyStatus != "incomplete_response_body" {
		t.Fatalf("lost declared-length or incomplete-body qualification: %d %v %s", row.ResContentLength, row.ParseQualifications, row.ReassemblyStatus)
	}
	var exact bool
	for _, header := range row.ResponseHeaders {
		if string(header.Name) == "Content-Length" && string(header.Value) == " 4497694720" {
			exact = true
		}
	}
	if !exact {
		t.Fatal("missing original Content-Length header")
	}
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if health.Exceeded || health.RetainedBytes != 0 || health.PeakBytes > health.LimitBytes {
		t.Fatal(health)
	}
	t.Logf("admitted=%d length=%d qualification=%q credits=%d", m.AdmittedPackets, rows[0].ResContentLength, rows[0].ReassemblyStatus, health.PeakBytes)
}
