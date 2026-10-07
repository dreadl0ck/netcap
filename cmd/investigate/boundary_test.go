package investigate

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
)

func TestProtocolFieldsCLITLVAndFailureEvidence(t *testing.T) {
	grammar := protocoltest.Grammar{Version: 1, Framing: protocoltest.Framing{Kind: "length-prefix", LengthBytes: 1, ByteOrder: "big", MaxBytes: 64}, MaxFrames: 2, Fields: []protocoltest.FieldSpec{{Name: "records", Offset: 1, Kind: "tlv", TLV: &protocoltest.TLVSpec{TypeBytes: 1, LengthBytes: 1, ByteOrder: "big", NestedTypes: []uint64{16}, LeafKind: "utf8", MaxDepth: 2, MaxEntries: 8, MaxValueBytes: 32}}}}
	for _, valid := range []bool{true, false} {
		input := []byte{5, 16, 3, 1, 1, 'A'}
		if !valid {
			input = []byte{3, 1, 2, 'A'}
		}
		file := filepath.Join(t.TempDir(), "stream.bin")
		if err := os.WriteFile(file, input, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := GetCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		err := cmd.Run(context.Background(), []string{"investigate", "protocol-fields", "--spec", writeProtocolSpec(t, grammar), "--read", file})
		var report protocoltest.GrammarReport
		if e := json.Unmarshal(out.Bytes(), &report); e != nil {
			t.Fatal(e)
		}
		if valid {
			if err != nil || len(report.Frames) != 1 || report.Frames[0].Fields[0].Entries[0].Children[0].Offset != 3 {
				t.Fatal("TLV CLI", report, err)
			}
		} else if err == nil || report.Error == "" || report.Failure == nil || !bytes.Equal(report.Failure.Raw, input[1:]) || report.Failure.Offset != 1 {
			t.Fatal("failed hypothesis lost raw evidence", report, err)
		}
	}
}

func TestBoundaryCLISeparatesTargetRejectionAndHarnessStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		framing := protocoltest.Framing{Kind: "delimiter", Delimiter: []byte("\n"), MaxBytes: 64}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 3 {
				c, e := l.Accept()
				if e != nil {
					return
				}
				_ = c.SetDeadline(time.Now().Add(time.Second))
				b, e := framing.Read(c)
				if e == nil {
					reply := "ALIVE\n"
					if string(b) == "CHECK\n" {
						reply = "REJECT\n"
						if stop {
							reply = strings.Repeat("x", 100) + "\n"
						}
					}
					_, _ = c.Write([]byte(reply))
				}
				_ = c.Close()
			}
		}()
		control := protocoltest.Exchange{Version: 1, Network: "tcp", Address: l.Addr().String(), Framing: framing, MaxTotalBytes: 256, TimeoutMilliseconds: 500, Steps: []protocoltest.Step{{Send: []byte("PING\n"), Receive: true, Expect: []byte("ALIVE\n")}}}
		probe := control
		probe.Steps = []protocoltest.Step{{Send: []byte("CHECK\n"), Receive: true}}
		spec := protocoltest.BoundaryCase{Metadata: protocoltest.ExperimentMetadata{Version: 1, TargetVersion: "bounded-cli-fixture-v1", Reset: protocoltest.ResetSpec{Mode: "connection", Description: "fixture has no persistent state"}}, Name: "bounded-response", Control: control, Probe: probe, Accepted: []byte("ACCEPT\n"), Rejected: []byte("REJECT\n")}
		cmd := GetCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		err = cmd.Run(context.Background(), []string{"investigate", "protocol-boundary", "--spec", writeProtocolSpec(t, spec)})
		<-done
		var report protocoltest.BoundaryResult
		if e := json.Unmarshal(out.Bytes(), &report); e != nil {
			t.Fatal(e)
		}
		if stop {
			if err == nil || report.Qualified || report.Outcome != "harness-budget-stop" {
				t.Fatal("harness stop CLI", report, err)
			}
		} else if err != nil || !report.Qualified || report.Outcome != "target-rejected" {
			t.Fatal("target rejection CLI", report, err)
		}
		if report.After.Status != "matched" || report.Case.Metadata.TargetVersion != "bounded-cli-fixture-v1" {
			t.Fatal("control/provenance lost", report)
		}
	}
}
