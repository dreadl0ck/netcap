package protocoltest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This finite fixture exposes deterministic work/storage counters and file
// readback. It never invokes a shell and refuses requests above its tiny caps.
func resourceFixture(t *testing.T) (string, ExperimentMetadata) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "storage")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cpu, sum, expanded := 0, 0, 0
	address := fixtureService(t, func(c net.Conn) {
		b, err := lineExchange("").Framing.Read(c)
		if err != nil {
			return
		}
		parts := strings.SplitN(strings.TrimSuffix(string(b), "\n"), " ", 2)
		reply := "REJECT\n"
		switch parts[0] {
		case "RESET":
			cpu, sum, expanded = 0, 0, 0
			if os.WriteFile(file, nil, 0600) == nil {
				reply = "RESET-OK\n"
			}
		case "PING":
			reply = "ALIVE\n"
		case "STATS":
			data, e := os.ReadFile(file)
			if e == nil {
				reply = fmt.Sprintf("cpu=%d sum=%d storage=%d expansion=%d data=%s\n", cpu, sum, len(data), expanded, base64.StdEncoding.EncodeToString(data))
			}
		case "WAIT":
			var b [1]byte
			_, _ = c.Read(b[:])
			return
		case "LONG":
			reply = strings.Repeat("x", 300) + "\n"
		case "CPU", "EXPAND":
			if len(parts) == 2 {
				n, e := strconv.Atoi(parts[1])
				if e == nil && n >= 0 && n <= 64 {
					if parts[0] == "CPU" {
						for i := 0; i < n; i++ {
							cpu++
							sum += i
						}
					} else {
						data := bytes.Repeat([]byte("x"), n)
						expanded = len(data)
					}
					reply = "ACCEPT\n"
				}
			}
		case "STORE", "ENCODE":
			if len(parts) == 2 {
				data, e := base64.StdEncoding.DecodeString(parts[1])
				if e == nil && len(data) <= 32 && (parts[0] != "ENCODE" || !bytes.ContainsAny(data, "\n;\x00")) {
					if os.WriteFile(file, data, 0600) == nil {
						reply = "ACCEPT\n"
					}
				}
			}
		case "NEST":
			if len(parts) == 2 {
				data, e := hex.DecodeString(parts[1])
				if e == nil {
					s := tlvHypothesis()
					s.MaxDepth = 2
					s.MaxEntries = 8
					s.MaxValueBytes = 32
					if _, e = tlvGrammar(s).Interpret(tlvFrame(data)); e == nil {
						reply = "ACCEPT\n"
					}
				}
			}
		}
		_, _ = c.Write([]byte(reply))
	})
	reset := lineExchange(address, Step{Send: []byte("RESET\n"), Receive: true, Expect: []byte("RESET-OK\n")})
	metadata := fixtureMetadata()
	metadata.TargetVersion = "finite-resource-fixture-v1"
	metadata.Reset = ResetSpec{Mode: "exchange", Description: "zero operation/expansion counters and truncate fixture storage before each isolated run", Exchange: &reset}
	return address, metadata
}

func TestBoundaryFiniteNestedExpansionEncodingCPUAndStorageEffects(t *testing.T) {
	address, metadata := resourceFixture(t)
	encode := func(b string) string { return base64.StdEncoding.EncodeToString([]byte(b)) }
	cases := []struct {
		name, request       string
		accepted            bool
		cpu, sum, expansion int
		data                string
	}{
		{name: "nest-at-depth-two", request: "NEST 1003010141", accepted: true},
		{name: "nest-depth-three-rejected", request: "NEST 10051003010141"},
		{name: "expansion-at-64", request: "EXPAND 64", accepted: true, expansion: 64},
		{name: "expansion-65-rejected", request: "EXPAND 65"},
		{name: "cpu-at-64-operations", request: "CPU 64", accepted: true, cpu: 64, sum: 2016},
		{name: "cpu-65-rejected", request: "CPU 65"},
		{name: "storage-at-32-bytes", request: "STORE " + encode(strings.Repeat("s", 32)), accepted: true, data: strings.Repeat("s", 32)},
		{name: "storage-33-rejected", request: "STORE " + encode(strings.Repeat("s", 33))},
		{name: "encoded-value-control", request: "ENCODE " + encode("fixture"), accepted: true, data: "fixture"},
		{name: "encoded-newline-injection-rejected", request: "ENCODE " + encode("safe\nADMIN")},
		{name: "encoded-delimiter-injection-rejected", request: "ENCODE " + encode("safe;ADMIN")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verify := lineExchange(address, Step{Send: []byte("STATS\n"), Receive: true, Expect: []byte(fmt.Sprintf("cpu=%d sum=%d storage=%d expansion=%d data=%s\n", tc.cpu, tc.sum, len(tc.data), tc.expansion, encode(tc.data)))})
			spec := BoundaryCase{Metadata: metadata, Name: tc.name, Control: lineExchange(address, Step{Send: []byte("PING\n"), Receive: true, Expect: []byte("ALIVE\n")}), Probe: lineExchange(address, Step{Send: []byte(tc.request + "\n"), Receive: true}), Accepted: []byte("ACCEPT\n"), Rejected: []byte("REJECT\n"), Verification: &verify}
			r, err := RunBoundary(context.Background(), spec)
			want := "target-rejected"
			if tc.accepted {
				want = "target-accepted"
			}
			if err != nil || r.Outcome != want || !r.Qualified || r.Before.Status != "matched" || r.After.Status != "matched" || r.Verification == nil || r.Verification.Status != "matched" || len(r.Probe.Observations) != 2 || string(r.Probe.Observations[0].Bytes) != tc.request+"\n" {
				t.Fatalf("boundary outcome=%s qualified=%v err=%v", r.Outcome, r.Qualified, err)
			}
			if r.ProbeReset.Observation == nil || r.ProbeReset.Observation.Status != "matched" || len(r.ConfigurationSHA256) != 64 {
				t.Fatal("missing reset/config provenance")
			}
		})
	}
}

func TestBoundaryTargetRejectionIsNotHarnessTimeoutOrBudgetStop(t *testing.T) {
	address, metadata := resourceFixture(t)
	for _, tc := range []struct{ name, request, want string }{{"target-rejection", "CPU 65", "target-rejected"}, {"harness-timeout", "WAIT", "harness-timeout"}, {"harness-frame-budget", "LONG", "harness-budget-stop"}, {"harness-send-budget", "PING", "harness-budget-stop"}} {
		t.Run(tc.name, func(t *testing.T) {
			spec := BoundaryCase{Metadata: metadata, Name: tc.name, Control: lineExchange(address, Step{Send: []byte("PING\n"), Receive: true, Expect: []byte("ALIVE\n")}), Probe: lineExchange(address, Step{Send: []byte(tc.request + "\n"), Receive: true}), Accepted: []byte("ACCEPT\n"), Rejected: []byte("REJECT\n")}
			if tc.name == "harness-timeout" {
				spec.Probe.TimeoutMilliseconds = 40
			}
			if tc.name == "harness-send-budget" {
				spec.Probe.MaxTotalBytes = 1
			}
			start := time.Now()
			r, err := RunBoundary(context.Background(), spec)
			if r.Outcome != tc.want || r.After.Status != "matched" || time.Since(start) > time.Second {
				t.Fatalf("outcome=%s postcontrol=%s err=%v", r.Outcome, r.After.Status, err)
			}
			if tc.want == "target-rejected" {
				if err != nil || !r.Qualified {
					t.Fatal("explicit target rejection not qualified")
				}
			} else if err == nil || r.Qualified {
				t.Fatal("harness failure promoted to target finding")
			}
			if tc.name == "harness-frame-budget" && (len(r.Probe.Observations) != 2 || len(r.Probe.Observations[1].Bytes) != 128) {
				t.Fatal("bounded partial frame evidence lost")
			}
		})
	}
}
