/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"encoding/json"
	"testing"
)

func TestExtractSessionErrorLocalMode(t *testing.T) {
	ref := SessionRef{ID: "/data/x.pcap", isPath: true}
	body := json.RawMessage(`[
        {"path":"/data/x.pcap","name":"x.pcap","isCompleted":false,"error":"tcpdump exit 1","errorLogPath":"/data/x.pcap.err.log"},
        {"path":"/data/y.pcap","name":"y.pcap","isCompleted":true}
    ]`)
	msg, logPath, status, found := extractSessionError(ref, body)
	if !found {
		t.Fatal("expected to find row")
	}
	if msg != "tcpdump exit 1" {
		t.Errorf("msg = %q", msg)
	}
	if logPath != "/data/x.pcap.err.log" {
		t.Errorf("logPath = %q", logPath)
	}
	if status != "" {
		t.Errorf("status = %q (expected empty for local mode)", status)
	}
}

func TestExtractSessionErrorServiceMode(t *testing.T) {
	ref := SessionRef{ID: "abcdef0123456789", isPath: false}
	body := json.RawMessage(`[
        {"sessionId":"abcdef0123456789","name":"x.pcap","isCompleted":false,"status":"failed","error":"out of memory","errorLogPath":""},
        {"sessionId":"feedbeef","name":"y.pcap","isCompleted":true,"status":"completed"}
    ]`)
	msg, _, status, found := extractSessionError(ref, body)
	if !found {
		t.Fatal("expected to find row")
	}
	if msg != "out of memory" {
		t.Errorf("msg = %q", msg)
	}
	if status != "failed" {
		t.Errorf("status = %q", status)
	}
}

func TestExtractSessionErrorEmptyBody(t *testing.T) {
	ref := SessionRef{ID: "x", isPath: false}
	if _, _, _, found := extractSessionError(ref, nil); found {
		t.Error("nil body should produce found=false")
	}
	if _, _, _, found := extractSessionError(ref, json.RawMessage("not json")); found {
		t.Error("malformed body should produce found=false")
	}
}
