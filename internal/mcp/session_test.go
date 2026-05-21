/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewSessionRef checks the path/hex heuristic on representative ids.
func TestNewSessionRef(t *testing.T) {
	cases := []struct {
		in       string
		wantPath bool
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", false}, // 32-char hex → service
		{"D41D8CD98F00B204E9800998ECF8427E", false},
		{"/tmp/sample.pcap", true},
		{"C:\\captures\\sample.pcapng", true},
		{"sample.pcap", true},
		{"sample.cap", true},
		{"sample.dmp", true},
		{"some-other-string", false}, // unknown → not a path
		{"", false},
	}
	for _, c := range cases {
		got := newSessionRef(c.in)
		if got.isPath != c.wantPath {
			t.Errorf("newSessionRef(%q).isPath = %v, want %v", c.in, got.isPath, c.wantPath)
		}
		if got.ID != c.in {
			t.Errorf("newSessionRef(%q).ID = %q, want %q", c.in, got.ID, c.in)
		}
	}
}

// TestSessionGateSerialises verifies the gate enforces serial execution
// of (selectSession, call) pairs. Two goroutines hold the gate for 50 ms
// each; the second must wait for the first.
func TestSessionGateSerialises(t *testing.T) {
	g := sessionGate{}
	var inflight int32
	var maxInflight int32

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = g.run(func() error {
				cur := atomic.AddInt32(&inflight, 1)
				for {
					old := atomic.LoadInt32(&maxInflight)
					if cur <= old || atomic.CompareAndSwapInt32(&maxInflight, old, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&inflight, -1)
				return nil
			})
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&maxInflight); got != 1 {
		t.Errorf("max concurrent gate holders = %d, want 1", got)
	}
}

// TestNormaliseServiceSession checks the upstream→MCP shape translation.
func TestNormaliseServiceSession(t *testing.T) {
	in := map[string]any{
		"sessionId":     "abc",
		"inputFile":     "/data/x.pcap",
		"inputFilename": "x.pcap",
		"inputFileSize": 1234,
		"status":        "completed",
		"resultsReady":  true,
		"shareUrl":      "/view/abc",
		"isPreloaded":   false,
	}
	out := normaliseServiceSession(in)
	if out["session_id"] != "abc" {
		t.Errorf("session_id = %v", out["session_id"])
	}
	if out["completed"] != true {
		t.Errorf("completed = %v", out["completed"])
	}
}

// TestNormaliseLocalFile checks the local-mode path→session translation.
func TestNormaliseLocalFile(t *testing.T) {
	in := map[string]any{
		"id":          "hash123",
		"name":        "x.pcap",
		"path":        "/data/x.pcap",
		"size":        1234,
		"isCompleted": true,
	}
	out := normaliseLocalFile(in)
	if out["session_id"] != "/data/x.pcap" {
		t.Errorf("session_id = %v", out["session_id"])
	}
	if out["completed"] != true {
		t.Errorf("completed = %v", out["completed"])
	}
	if out["file_id"] != "hash123" {
		t.Errorf("file_id = %v", out["file_id"])
	}
}
