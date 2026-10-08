package investigate

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestInvestigationCLIFlowAndEvidence(t *testing.T) {
	dir := t.TempDir()
	records := filepath.Join(dir, "Connection.ncap.gz")
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	writer := delimited.NewWriter(gz)
	if err := writer.PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		t.Fatal(err)
	}
	if err := writer.PutProto(&types.Connection{ObservationID: "fixture", CounterSemantics: "tuple-cumulative", SnapshotSequence: 1, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TotalSize64: 600000000, NumPackets64: 10, TimestampLast: 60000000000}); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(records, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := GetCommand()
	command.Writer = &output
	command.ErrWriter = &output
	if err := command.Run(context.Background(), []string{"investigate", "flows", "--read", records, "--start-ns", "0", "--end-ns", "60000000000"}); err != nil {
		t.Fatal(err)
	}
	var result flow.FileResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Matched != 1 || result.Groups[0].AverageBitsPerSecond != 80000000 || result.RecordFileSHA256 == "" {
		t.Fatalf("CLI flow result: %+v", result)
	}

	data.Reset()
	pw := pcapgo.NewWriterNanos(&data)
	if err := pw.WriteFileHeader(128, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := pw.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 2), CaptureLength: 14, Length: 14}, make([]byte, 14)); err != nil {
		t.Fatal(err)
	}
	input, target := filepath.Join(dir, "input.pcap"), filepath.Join(dir, "evidence.zip")
	if err := os.WriteFile(input, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	command = GetCommand()
	command.Writer = &output
	command.ErrWriter = &output
	args := []string{"investigate", "packet-evidence", "--read", input, "--out", target}
	if err := command.Run(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	var manifest evidence.PacketManifest
	if err := json.Unmarshal(output.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Selected != 1 || manifest.OutputSHA256 == "" {
		t.Fatalf("CLI packet result: %+v", manifest)
	}
	want, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	command = GetCommand()
	command.Writer = &output
	command.ErrWriter = &output
	if err := command.Run(context.Background(), args); err == nil {
		t.Fatal("overwrote existing evidence")
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("failed publication changed existing evidence")
	}
	output.Reset()
	command = GetCommand()
	command.Writer = &output
	command.ErrWriter = &output
	empty := filepath.Join(dir, "empty.zip")
	if err := command.Run(context.Background(), []string{"investigate", "packet-evidence", "--read", input, "--out", empty, "--bpf", "len > 1000"}); err == nil {
		t.Fatal("empty export qualified")
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Fatalf("empty artifact published: %v", err)
	}
}
