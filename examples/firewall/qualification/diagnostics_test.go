//go:build coraza && http3

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type byteReader struct{ io.Reader }

func (r byteReader) Read(b []byte) (int, error) { return r.Reader.Read(b[:min(len(b), 1)]) }

func TestWebSocketSplitReadAndTruncatedDenial(t *testing.T) {
	b, err := wsRead(bufio.NewReader(byteReader{strings.NewReader("\x81\x04safe")}), false)
	if err != nil || string(b) != "safe" {
		t.Fatalf("split read: %q %v", b, err)
	}
	for _, tc := range []struct {
		wire, category, stage string
		denied                bool
	}{
		{"", "eof", "ws-frame-header", true},
		{"\x81", "partial-eof", "ws-frame-header", false},
		{"\x81\x04sa", "partial-eof", "ws-frame-body", false},
		{"\x82\x00", "invalid-frame", "ws-frame-header", false},
	} {
		_, err := wsRead(bufio.NewReader(strings.NewReader(tc.wire)), false)
		f := describeFailure(err)
		if f.Category != tc.category || f.Stage != tc.stage || wsDeniedCleanly(err) != tc.denied {
			t.Fatalf("wire=%x diagnostic=%+v denied=%v", tc.wire, f, wsDeniedCleanly(err))
		}
	}
}

func TestWebSocketFaultDuringPartialFrameIsNotDenial(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); defer peer.Close(); _, _ = peer.Write([]byte{129}) }()
	_, err := wsRead(bufio.NewReader(client), false)
	<-done
	if wsDeniedCleanly(err) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("fault accepted: %v", err)
	}
	f := describeFailure(err)
	if f.Stage != "ws-frame-header" || f.Read != 1 || f.Want != 2 {
		t.Fatalf("lost context: %+v", f)
	}
}

func TestWebSocketStalledFramePreservesTimeout(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := wsRead(bufio.NewReader(client), false)
	if wsDeniedCleanly(err) || describeFailure(err).Category != "timeout" {
		t.Fatalf("timeout accepted: %v", err)
	}
}

func TestFailureDiagnosticsDoNotSerializeCredentialsOrPayload(t *testing.T) {
	err := wireStage("ws-handshake-read", errors.New("https://user:secret@host/?token=secret payload=private"))
	b, e := json.Marshal(describeFailure(err))
	if e != nil || strings.Contains(string(b), "secret") || strings.Contains(string(b), "private") {
		t.Fatalf("unsafe diagnostic: %s %v", b, e)
	}
}

func TestFaultReceiptPreservesFailedRecovery(t *testing.T) {
	p, err := newProfile(context.Background(), 0, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { p.Close() }()
	calls := 0
	p.CustomRequest = func(workflow) (int, int, error) {
		calls++
		if calls == 1 {
			return 503, 1, nil
		}
		return 0, 0, &net.DNSError{Err: "secret", IsTimeout: true}
	}
	receipt, err := p.exerciseFault(context.Background(), 7)
	if err == nil || receipt["stage"] != "recovery-allow" || receipt["result"] != "fail" || receipt["generation"] != 7 {
		t.Fatalf("lost failed fault: %v %+v", err, receipt)
	}
	f := receipt["failure"].(requestFailure)
	if f.Stage != "fault-recovery-allow" || f.Category != "timeout" {
		t.Fatalf("lost cause: %+v", f)
	}
	b, e := json.Marshal(receipt)
	if e != nil || strings.Contains(string(b), "secret") {
		t.Fatalf("unsafe receipt: %s %v", b, e)
	}
}
