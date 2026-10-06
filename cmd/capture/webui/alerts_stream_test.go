package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

type testSSE struct{ event, id, data string }

func readTestSSE(t *testing.T, reader *bufio.Reader) testSSE {
	t.Helper()
	var event testSSE
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			return event
		}
		if value, ok := strings.CutPrefix(line, "event: "); ok {
			event.event = value
		}
		if value, ok := strings.CutPrefix(line, "id: "); ok {
			event.id = value
		}
		if value, ok := strings.CutPrefix(line, "data: "); ok {
			event.data = value
		}
	}
}

func TestLiveAlertStreamAndReconnect(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir, baseOutDir: dir, shutdownChan: make(chan struct{})}
	server := httptest.NewServer(http.HandlerFunc(s.handleAlertsStream))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if event := readTestSSE(t, reader); event.event != "connected" {
		t.Fatalf("first event = %+v", event)
	}
	w, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	started := time.Now()
	if err := w.WriteAlert(&types.Alert{Name: "first", Timestamp: 1700000000000000000}); err != nil {
		t.Fatal(err)
	}
	first := readTestSSE(t, reader)
	if first.event != "alert" || first.id == "" {
		t.Fatalf("first alert = %+v", first)
	}
	var alert AlertResponse
	if err := json.Unmarshal([]byte(first.data), &alert); err != nil {
		t.Fatal(err)
	}
	if alert.Name != "first" || alert.Timestamp != 1700000000000 {
		t.Fatalf("alert = %+v", alert)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("local stream exceeded 1s: %s", elapsed)
	}
	_ = response.Body.Close()
	if err := w.WriteAlert(&types.Alert{Name: "second"}); err != nil {
		t.Fatal(err)
	}
	reconnect, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	reconnect.Header.Set("Last-Event-ID", first.id)
	resumed, err := http.DefaultClient.Do(reconnect)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Body.Close()
	r := bufio.NewReader(resumed.Body)
	if event := readTestSSE(t, r); event.event != "connected" {
		t.Fatalf("reconnect = %+v", event)
	}
	second := readTestSSE(t, r)
	if err := json.Unmarshal([]byte(second.data), &alert); err != nil {
		t.Fatal(err)
	}
	if second.event != "alert" || alert.Name != "second" || second.id == first.id {
		t.Fatalf("resume repeated/lost alert: %+v", second)
	}
}

func TestAlertStreamLimitsAndInvalidCursor(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir, baseOutDir: dir, alertStreams: 8}
	response := httptest.NewRecorder()
	s.handleAlertsStream(response, httptest.NewRequest(http.MethodGet, "/api/alerts/stream", nil))
	if response.Code != http.StatusTooManyRequests || s.alertStreams != 8 {
		t.Fatal("stream limit failed")
	}
	s.alertStreams = 0
	w, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.WriteAlert(&types.Alert{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/alerts/stream", nil)
	request.Header.Set("Last-Event-ID", "wrong:0:0")
	s.handleAlertsStream(response, request)
	if response.Code != http.StatusConflict || s.alertStreams != 0 {
		t.Fatalf("cursor = %d; streams = %d", response.Code, s.alertStreams)
	}
}

func TestBehaviorAlertIDsIncludeFactEvidence(t *testing.T) {
	a := AlertResponse{RuleName: "baseline.new-service", Timestamp: 1, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", RecordType: "Behavior", MatchedRecord: `{"port":22}`}
	b := a
	b.MatchedRecord = `{"port":3389}`
	if generateAlertID(a) == generateAlertID(b) {
		t.Fatal("same-millisecond behavioral facts collide")
	}
	a.RecordType = "TCP"
	if got := generateAlertID(a); got != "baseline.new-service-1-192.0.2.1-192.0.2.2" {
		t.Fatalf("legacy ID changed: %s", got)
	}
}
