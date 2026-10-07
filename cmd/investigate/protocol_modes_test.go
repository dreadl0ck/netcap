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

type addressWriter struct{ address chan string }

func (w addressWriter) Write(b []byte) (int, error) {
	words := strings.Fields(string(b))
	if len(words) > 0 {
		select {
		case w.address <- words[len(words)-1]:
		default:
		}
	}
	return len(b), nil
}
func writeProtocolSpec(t *testing.T, spec any) string {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "spec.json")
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestUDPServerCLIExecutesStatefulSession(t *testing.T) {
	spec := protocoltest.Exchange{Version: 1, Network: "udp", Address: "127.0.0.1:0", Framing: protocoltest.Framing{MaxBytes: 64}, MaxTotalBytes: 256, TimeoutMilliseconds: 2000, Steps: []protocoltest.Step{{Receive: true, CaptureVariable: "fresh", CaptureLength: 4}, {SendVariable: "fresh"}}}
	var output bytes.Buffer
	cmd := GetCommand()
	cmd.Writer = &output
	address := make(chan string, 1)
	cmd.ErrWriter = addressWriter{address}
	done := make(chan error, 1)
	file := writeProtocolSpec(t, spec)
	go func() {
		done <- cmd.Run(context.Background(), []string{"investigate", "protocol-server", "--spec", file})
	}()
	select {
	case spec.Address = <-address:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not announce address")
	}
	spec.Steps = []protocoltest.Step{{Send: []byte{0, 1, 255, 2}, Receive: true, Expect: []byte{0, 1, 255, 2}}}
	if _, err := protocoltest.Run(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var r protocoltest.Result
	if err := json.Unmarshal(output.Bytes(), &r); err != nil || r.Status != "matched" || len(r.Observations) != 2 {
		t.Fatal("UDP CLI evidence", r, err)
	}
}

func TestGenerateFuzzAndReproduceCLI(t *testing.T) {
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 128)
		for {
			n, peer, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			response := []byte("VALID")
			if bytes.Contains(b[:n], []byte{0xbe}) {
				response = []byte("FAIL")
			}
			_, _ = p.WriteTo(response, peer)
		}
	}()
	defer func() { _ = p.Close(); <-done }()
	control := protocoltest.Exchange{Version: 1, Network: "udp", Address: p.LocalAddr().String(), Framing: protocoltest.Framing{MaxBytes: 64}, MaxTotalBytes: 256, TimeoutMilliseconds: 1000, Steps: []protocoltest.Step{{Send: []byte("AA"), Receive: true, Expect: []byte("VALID")}}}
	spec := protocoltest.Campaign{Metadata: protocoltest.ExperimentMetadata{Version: 1, TargetVersion: "cli-fixture-v1", Reset: protocoltest.ResetSpec{Mode: "connection", Description: "stateless UDP fixture; fresh client port and variables"}}, Control: control, FailureMarker: []byte("FAIL"), MaxCases: 16, MaxAttempts: 32}
	run := func(name string, value any) []byte {
		t.Helper()
		cmd := GetCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		cmd.ErrWriter = &out
		if err := cmd.Run(context.Background(), []string{"investigate", name, "--spec", writeProtocolSpec(t, value)}); err != nil {
			t.Fatalf("%s: %v %s", name, err, out.String())
		}
		return bytes.Clone(out.Bytes())
	}
	var corpus protocoltest.GeneratedCorpus
	if err := json.Unmarshal(run("protocol-generate", spec), &corpus); err != nil || len(corpus.Cases) != 5 || corpus.GenerationVersion != protocoltest.GenerationVersion {
		t.Fatal("generate CLI", corpus, err)
	}
	var campaign protocoltest.CampaignResult
	if err := json.Unmarshal(run("protocol-fuzz", spec), &campaign); err != nil || campaign.MinimizedCase == nil || !campaign.MinimizationComplete {
		t.Fatal("fuzz CLI", campaign, err)
	}
	var reproduced protocoltest.ReproductionResult
	if err := json.Unmarshal(run("protocol-reproduce", protocoltest.ReproductionSpec{Metadata: spec.Metadata, Case: *campaign.MinimizedCase, FailureMarker: spec.FailureMarker}), &reproduced); err != nil || !reproduced.Trial.FailureMarkerReturned || reproduced.Spec.Metadata.TargetVersion != "cli-fixture-v1" {
		t.Fatal("reproduction CLI", reproduced, err)
	}
}
