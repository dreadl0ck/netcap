package protocoltest

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The handler owns session state; tests own persistent fixture state explicitly.
func fixtureService(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	l := loopback(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			handler(c)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done })
	return l.Addr().String()
}

func TestGeneratedGrammarFieldCampaignAndExactReproduction(t *testing.T) {
	framing := Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 64}
	address := fixtureService(t, func(c net.Conn) {
		b, e := framing.Read(c)
		if e == nil {
			response := []byte{0, 1, 0}
			if len(b) == 4 && b[2] == 255 {
				response[2] = 255
			}
			_, _ = c.Write(response)
		}
	})
	grammar := Grammar{Version: 1, Framing: framing, MaxFrames: 1, Fields: []FieldSpec{{Name: "opcode", Offset: 2, Length: 2, Kind: "unsigned", ByteOrder: "little", Expected: []byte{1, 0}, Hypothesis: "fixture operation selector"}}}
	control := Exchange{Version: 1, Network: "tcp", Address: address, Framing: framing, MaxTotalBytes: 256, TimeoutMilliseconds: 500, Steps: []Step{{SendPresent: true, Receive: true, Expect: []byte{0, 1, 0}}}}
	spec := Campaign{Metadata: fixtureMetadata(), Control: control, FailureMarker: []byte{255}, MaxCases: 16, MaxAttempts: 32, Generation: &GenerationSpec{Version: 1, Grammar: &grammar, BuildSeed: true, Fields: []FieldMutation{{Name: "opcode"}}}}
	a, err := GenerateCampaign(spec)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateCampaign(spec)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if err != nil || !bytes.Equal(ja, jb) || len(a.Cases) != 5 || a.GenerationVersion != GenerationVersion || a.Metadata.TargetVersion != "loopback-fixture-v1" || !bytes.Equal(a.Cases[0].Exchange.Steps[0].Send, []byte{0, 2, 1, 0}) {
		t.Fatalf("grammar corpus %+v %v", a, err)
	}
	r, err := RunCampaign(context.Background(), spec)
	if err != nil || !r.MinimizationComplete || r.MinimizedCase == nil || !bytes.Equal(r.Minimized.Input, []byte{0, 2, 255, 0}) || r.Reproduction == nil || !r.Reproduction.FailureMarkerReturned || r.Before.Status != "matched" || r.After.Status != "matched" {
		t.Fatalf("field campaign %+v %v", r, err)
	}
	replay := ReproductionSpec{Metadata: spec.Metadata, Case: *r.MinimizedCase, FailureMarker: spec.FailureMarker}
	reproduced, err := Reproduce(context.Background(), replay)
	if err != nil || !reproduced.Trial.FailureMarkerReturned || !bytes.Equal(reproduced.Trial.Result.Observations[0].Bytes, r.Minimized.Input) {
		t.Fatalf("reproduction %+v %v", reproduced, err)
	}
	replay.Case.ConfigurationSHA256 = "tampered"
	if _, err = Reproduce(context.Background(), replay); err == nil {
		t.Fatal("tampered reproduction accepted")
	}
	spec.Generation.Version = 99
	if _, err = GenerateCampaign(spec); err == nil {
		t.Fatal("unknown generator accepted")
	}
	grammar.Fields[0].Offset = 3
	if _, err = GrammarSeed(grammar); err == nil {
		t.Fatal("unspecified grammar byte silently invented")
	}
}

func TestStateGenerationMinimizationAndControls(t *testing.T) {
	address := fixtureService(t, func(c net.Conn) {
		logins := 0
		f := lineExchange("").Framing
		for {
			b, e := f.Read(c)
			if e != nil {
				return
			}
			reply := "OK\n"
			switch string(b) {
			case "LOGIN\n":
				logins++
			case "READ\n":
				reply = "VALID\n"
				if logins >= 2 {
					reply = "DUPLICATE-STATE-MARKER\n"
				}
			}
			_, _ = c.Write([]byte(reply))
		}
	})
	control := lineExchange(address, Step{Send: []byte("NOOP\n"), Receive: true, Expect: []byte("OK\n")}, Step{Send: []byte("LOGIN\n"), Receive: true, Expect: []byte("OK\n")}, Step{Send: []byte("READ\n"), Receive: true, Expect: []byte("VALID\n")})
	spec := Campaign{Metadata: fixtureMetadata(), Control: control, SendStep: 2, ResponseStep: 2, FailureMarker: []byte("DUPLICATE-STATE-MARKER"), MaxCases: 16, MaxAttempts: 32, Generation: &GenerationSpec{Version: 1, States: []StateMutation{{Action: "omit", Step: 1}, {Action: "swap-next", Step: 0}, {Action: "duplicate", Step: 1}}}}
	generated, err := GenerateCampaign(spec)
	if err != nil || len(generated.Cases) != 4 {
		t.Fatal("state generation", generated, err)
	}
	r, err := RunCampaign(context.Background(), spec)
	if err != nil || !r.MinimizationComplete || r.MinimizedCase == nil || r.MinimizedCase.SendStep != 2 || len(r.MinimizedCase.Exchange.Steps) != 3 || string(r.MinimizedCase.Exchange.Steps[0].Send) != "LOGIN\n" || string(r.MinimizedCase.Exchange.Steps[1].Send) != "LOGIN\n" || r.After.Status != "matched" {
		t.Fatalf("state campaign %+v %v", r, err)
	}
	if _, err = Reproduce(context.Background(), ReproductionSpec{Metadata: spec.Metadata, Case: *r.MinimizedCase, FailureMarker: spec.FailureMarker}); err != nil {
		t.Fatal(err)
	}
	spec.Generation.States[0].Action = "arbitrary-code"
	if _, err = GenerateCampaign(spec); err == nil {
		t.Fatal("unknown state mutation accepted")
	}
}

func TestRoleResourceMatrixResetsPersistentStateEveryCase(t *testing.T) {
	var resets, reads atomic.Int32
	dirty := false
	address := fixtureService(t, func(c net.Conn) {
		role := "anonymous"
		f := lineExchange("").Framing
		for {
			b, e := f.Read(c)
			if e != nil {
				return
			}
			fields := strings.Fields(string(b))
			reply := "DENIED\n"
			if len(fields) == 1 && fields[0] == "RESET" {
				dirty = false
				resets.Add(1)
				reply = "RESET-OK\n"
			} else if len(fields) == 2 && fields[0] == "LOGIN" {
				role = fields[1]
				reply = "OK\n"
			} else if len(fields) == 2 && fields[0] == "READ" {
				reads.Add(1)
				resource := path.Clean(fields[1])
				if dirty {
					reply = "DIRTY\n"
				} else if resource == "/"+role+"/fixture" && role != "anonymous" {
					reply = strings.ToUpper(role) + "-PRIVATE\n"
				}
				dirty = true
			}
			_, _ = c.Write([]byte(reply))
		}
	})
	reset := lineExchange(address, Step{Send: []byte("RESET\n"), Receive: true, Expect: []byte("RESET-OK\n")})
	metadata := fixtureMetadata()
	metadata.Reset = ResetSpec{Mode: "exchange", Description: "fixture RESET clears persistent dirty flag before each resource request", Exchange: &reset}
	cases := []AccessCase{}
	for _, role := range []string{"anonymous", "alice", "bob"} {
		for _, resource := range []string{"/alice/fixture", "/bob/fixture", "/alice/../bob/fixture"} {
			owner := "alice"
			if path.Clean(resource) == "/bob/fixture" {
				owner = "bob"
			}
			steps := []Step{}
			if role != "anonymous" {
				steps = append(steps, Step{Send: []byte("LOGIN " + role + "\n"), Receive: true, Expect: []byte("OK\n")})
			}
			steps = append(steps, Step{Send: []byte("READ " + resource + "\n"), Receive: true})
			cases = append(cases, AccessCase{Metadata: metadata, Role: role, State: "read", Resource: resource, Message: "READ", Allowed: role == owner, Marker: []byte(strings.ToUpper(owner) + "-PRIVATE"), ResponseStep: len(steps) - 1, Exchange: lineExchange(address, steps...)})
		}
	}
	r, err := RunAccess(context.Background(), cases)
	if err != nil || resets.Load() != 9 || reads.Load() != 9 {
		t.Fatal("reset count", resets.Load(), reads.Load(), err)
	}
	for _, o := range r {
		if o.Status != "matched" || o.Reset.Observation == nil || o.Reset.Observation.Status != "matched" || string(o.Reset.Observation.Observations[0].Bytes) != "RESET\n" {
			t.Fatalf("matrix reset/evidence %+v", o)
		}
	}
	// Deliberately remove the reset and demonstrate state contamination, rather than assuming it.
	control := cases[3]
	control.Metadata = fixtureMetadata()
	r, err = RunAccess(context.Background(), []AccessCase{control})
	if err != nil || r[0].Status != "boundary-mismatch" {
		t.Fatal("negative reset control failed", r, err)
	}
	reset.Steps[0].Expect = []byte("WRONG-ACK\n")
	before := reads.Load()
	r, err = RunAccess(context.Background(), []AccessCase{cases[0]})
	if err != nil || r[0].Status != "inconclusive" || reads.Load() != before || r[0].Reset.Observation.Status != "error" || r[0].Reset.Isolation != "reset failed; target exchange not started" {
		t.Fatal("failed reset ran target", r, err)
	}
}

func TestCampaignResetBeforeEveryTrialAndControl(t *testing.T) {
	var resets atomic.Int32
	dirty := false
	address := fixtureService(t, func(c net.Conn) {
		b, e := lineExchange("").Framing.Read(c)
		if e != nil {
			return
		}
		reply := "VALID\n"
		switch string(b) {
		case "RESET\n":
			dirty = false
			resets.Add(1)
			reply = "RESET-OK\n"
		default:
			if dirty {
				reply = "DIRTY\n"
			} else if bytes.Contains(b, []byte("!")) {
				reply = "FAIL\n"
			}
			dirty = true
		}
		_, _ = c.Write([]byte(reply))
	})
	reset := lineExchange(address, Step{Send: []byte("RESET\n"), Receive: true, Expect: []byte("RESET-OK\n")})
	metadata := fixtureMetadata()
	metadata.Reset = ResetSpec{Mode: "exchange", Description: "clear dirty fixture before every run", Exchange: &reset}
	grammar := Grammar{Version: 1, Framing: lineExchange("").Framing, MaxFrames: 1, Fields: []FieldSpec{{Name: "opcode", Offset: 0, Length: 1, Kind: "bytes"}}}
	spec := Campaign{Metadata: metadata, Control: lineExchange(address, Step{Send: []byte("A\n"), Receive: true, Expect: []byte("VALID\n")}), FailureMarker: []byte("FAIL"), MaxCases: 8, MaxAttempts: 8, Generation: &GenerationSpec{Version: 1, Grammar: &grammar, Fields: []FieldMutation{{Name: "opcode", Values: [][]byte{[]byte("!")}}}}}
	r, err := RunCampaign(context.Background(), spec)
	if err != nil || !r.MinimizationComplete || r.After.Status != "matched" || int(resets.Load()) != len(r.Trials)+2 {
		t.Fatalf("campaign resets %+v %v resets=%d", r, err, resets.Load())
	}
	for _, trial := range r.Trials {
		if trial.Reset.Observation == nil || trial.Reset.Observation.Status != "matched" {
			t.Fatal("trial missing reset evidence")
		}
	}
}

func TestExternalIntegrationImportsVersionsHashesAndLimits(t *testing.T) {
	for _, kind := range []string{"routing", "socket-trace", "debugger", "decompiler", "reset", "sanitizer", "process", "impact"} {
		t.Run(kind, func(t *testing.T) {
			input := []byte{0, 2, 1, 0}
			raw := []byte("fixture tool v1\noriginal-destination=127.0.0.1:1234\nbefore=direct after=loopback-proxy\nstack=fixture:42\n")
			file := filepath.Join(t.TempDir(), "artifact.txt")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			a, err := ImportGeneratedTriage(kind, "target-v7", "fixture restarted", "fixture-generator/config-v3", input, file)
			if err != nil || a.GenerationVersion != GenerationVersion || a.InputGeneration != "fixture-generator/config-v3" || a.TargetVersion != "target-v7" || !bytes.Equal(a.Evidence, raw) || !bytes.Equal(a.Input, input) || len(a.ConfigurationSHA256) != 64 || len(a.InputSHA256) != 64 || a.Classification != "external evidence; impact unverified" {
				t.Fatalf("artifact %+v %v", a, err)
			}
			b, err := ImportGeneratedTriage(kind, "target-v7", "fixture restarted", "fixture-generator/config-v3", input, file)
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			if err != nil || !bytes.Equal(ja, jb) {
				t.Fatal("non-deterministic artifact import")
			}
			if err = os.WriteFile(file, bytes.Repeat([]byte{0}, (1<<20)+1), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = ImportGeneratedTriage(kind, "v1", "reset", "g1", input, file); err == nil {
				t.Fatal("oversized artifact accepted")
			}
		})
	}
}

func TestGenerationSupportedFramingsAndExplicitRejections(t *testing.T) {
	for _, f := range []Framing{{Kind: "fixed", FixedSize: 2, MaxBytes: 8}, {Kind: "delimiter", Delimiter: []byte("\n"), MaxBytes: 8}, {Kind: "length-prefix", LengthBytes: 1, LengthIncludesHeader: true, ByteOrder: "big", MaxBytes: 8}} {
		offset := 0
		if f.Kind == "length-prefix" {
			offset = 1
		}
		g := Grammar{Version: 1, Framing: f, MaxFrames: 1, Fields: []FieldSpec{{Name: "value", Offset: offset, Length: 2, Kind: "signed", ByteOrder: "big", Expected: []byte{0, 1}}}}
		seed, err := GrammarSeed(g)
		if err != nil {
			t.Fatal(f.Kind, err)
		}
		report, err := g.Interpret(seed)
		if err != nil || len(report.Frames) != 1 {
			t.Fatal("constructed frame invalid", f, err)
		}
		control := lineExchange("127.0.0.1:1", Step{Send: seed, Receive: true})
		control.Framing = f
		spec := Campaign{Metadata: fixtureMetadata(), Control: control, MaxCases: 8, Generation: &GenerationSpec{Version: 1, Grammar: &g, Fields: []FieldMutation{{Name: "value"}}}}
		corpus, err := GenerateCampaign(spec)
		if err != nil || !bytes.Equal(corpus.Cases[4].Exchange.Steps[0].Send[offset:offset+2], []byte{128, 0}) {
			t.Fatal("signed boundary generation", corpus, err)
		}
		spec.MaxCases = 1
		if _, err = GenerateCampaign(spec); err == nil {
			t.Fatal("case limit silently truncated")
		}
		spec.MaxCases = 8
		spec.Generation.Fields[0].Values = [][]byte{{1}}
		if _, err = GenerateCampaign(spec); err == nil {
			t.Fatal("variable-width mutation accepted")
		}
		spec.Generation.Fields[0].Values = nil
		spec.Generation.Grammar.Fields[0].Kind = "tlv"
		if _, err = GenerateCampaign(spec); err == nil {
			t.Fatal("unsupported nested grammar accepted")
		}
	}
	metadata := fixtureMetadata()
	metadata.Reset.Mode = "shell"
	if metadata.Validate() == nil {
		t.Fatal("external command reset silently accepted")
	}
	metadata = fixtureMetadata()
	reset := lineExchange("127.0.0.1:1", Step{Send: []byte("RESET\n"), Receive: true})
	metadata.Reset = ResetSpec{Mode: "exchange", Description: "fixture reset", Exchange: &reset}
	if metadata.Validate() == nil {
		t.Fatal("unasserted reset accepted")
	}
}
