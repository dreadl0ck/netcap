//go:build coraza && http3

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIndependentLedgerNegativeControl(t *testing.T) {
	if err := negativeControl(); err != nil {
		t.Fatal(err)
	}
	l := &ledger{}
	l.ForbiddenBytes.Add(1)
	if checkLedger(l) == nil {
		t.Fatal("byte-only leak was ignored")
	}
}

func TestActualTransportsAndReloadPreserveBoundary(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		for _, crs := range []bool{false, true} {
			p, err := newProfile(context.Background(), 10, crs, proto)
			if err != nil {
				t.Fatal(err)
			}
			t.Run(p.Name, func(t *testing.T) {
				defer p.Close()
				for generation := 0; generation < 3; generation++ {
					policy, err := compile(10, generation)
					if err != nil {
						t.Fatal(err)
					}
					p.FW.SetPolicy(policy)
					status, actual, err := p.request(training[0])
					if err != nil || status != 200 || actual != proto {
						t.Fatalf("good request status=%d protocol=%d err=%v", status, actual, err)
					}
					status, actual, err = p.request(workflow{"late", "/api/invoices", "text/plain", strings.Repeat("a", 32000) + forbidden})
					if err != nil || status != 403 || actual != proto {
						t.Fatalf("late deny status=%d protocol=%d err=%v", status, actual, err)
					}
					if err := checkLedger(p.Ledger); err != nil {
						t.Fatal(err)
					}
				}
				if got := p.Ledger.Requests.Load(); got != 3 {
					t.Fatalf("independent origin count=%d, want 3", got)
				}
			})
		}
	}
}

func TestRepeatedHTTP3FaultRecovery(t *testing.T) {
	p, err := newProfile(context.Background(), 0, true, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { p.Close() }()
	var maxRecovery float64
	for generation := 1; generation <= 200; generation++ {
		receipt, err := p.exerciseFault(context.Background(), generation)
		if err != nil {
			t.Fatalf("generation=%d receipt=%v: %v", generation, receipt, err)
		}
		maxRecovery = max(maxRecovery, receipt["recovery_ms"].(float64))
	}
	t.Logf("owned HTTP3 restarts=200 max_recovery_ms=%.3f", maxRecovery)
}

func TestInterruptedRunPersistsFailureAndDoesNotClaim24h(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	err := run(ctx, options{Duration: 24 * time.Hour, Rate: 50, Workers: 2, Output: dir, Rules: "0", FaultEvery: time.Minute, MaxP99: time.Second, MinGoodput: 1, MaxHeap: 1 << 30})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wanted cancellation, got %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err = json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if report["load_state"] != "failed" || report["soak_24h_pass"] != false || report["qualification_state"] != "incomplete" {
		t.Fatalf("misleading interrupted report: %s", b)
	}
}

func TestHistogramTailIncludesSchedulingDelay(t *testing.T) {
	var s sample
	for i := 0; i < 95; i++ {
		s.observe(1)
	}
	for i := 0; i < 5; i++ {
		s.observe(1000)
	}
	if s.quantile(.95) != 1 || s.quantile(.99) != 1000 || s.MaxMS != 1000 {
		t.Fatalf("lost slow tail: %+v", s)
	}
}

func TestWholeRunnerRejectsDeliberateOriginLeak(t *testing.T) {
	dir := t.TempDir()
	err := run(context.Background(), options{Output: dir, Rules: "0", InjectLeak: true})
	if err == nil || !strings.Contains(err.Error(), "independent origin ledger") {
		t.Fatalf("harness accepted leak: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "negative-control.json")); err != nil {
		t.Fatal(err)
	}
}

func TestMixedOpenLoopBudgetAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	err := run(context.Background(), options{Duration: 5 * time.Second, Rate: 15, Workers: 64, Output: dir, Rules: "0", Mixed: true, FaultEvery: 2 * time.Second, MaxP99: 2 * time.Second, MinGoodput: 1, MaxHeap: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		LoadState string `json:"load_state"`
		Profiles  map[string]struct {
			Counts sample `json:"counts"`
		} `json:"profiles"`
		FaultCount int `json:"fault_count"`
	}
	if err = json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if report.LoadState != "pass" || len(report.Profiles) != 16 || report.FaultCount < 2 {
		t.Fatalf("mixed/lifecycle coverage missing: %s", b)
	}
	for name, p := range report.Profiles {
		if p.Counts.Allowed == 0 || p.Counts.Denied == 0 {
			t.Fatalf("profile got no mixed allow/deny load: %s %+v", name, p)
		}
	}
}

func TestFalsePositiveGateRequiresZeroBlocksWithoutWeakeningAttackControls(t *testing.T) {
	dir := t.TempDir()
	gateErr := run(context.Background(), options{Output: dir, Rules: "0", CorpusOnly: true})
	b, err := os.ReadFile(filepath.Join(dir, "falsepositives.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Result      string `json:"result"`
		FalseBlocks int    `json:"critical_false_blocks"`
		Cases       []struct {
			Split  string `json:"split"`
			Status int    `json:"status"`
		} `json:"owned_synthetic_cases"`
	}
	if err = json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if gateErr != nil || report.FalseBlocks != 0 || report.Result != "pass" {
		t.Fatalf("critical false-positive gate failed: %v %s", gateErr, b)
	}
	for _, row := range report.Cases {
		if row.Split == "attack-control" && row.Status != 403 {
			t.Fatal("attack control was suppressed")
		}
	}
}
