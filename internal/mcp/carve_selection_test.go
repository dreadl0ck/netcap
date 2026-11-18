package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestCarveCancellationStopsBackendAndDiscardsPartialData(t *testing.T) {
	for _, name := range []string{"carve_subpcap_for_host", "carve_subpcap_for_connection", "carve_subpcap_for_http_pair", "carve_subpcap_for_certificate"} {
		t.Run(name, func(t *testing.T) {
			started, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
				_, _ = w.Write([]byte("partial fixture"))
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-r.Context().Done():
					close(stopped)
				case <-release:
				}
			}))
			defer backend.Close()
			defer close(release)
			dir := t.TempDir()
			srv, err := New(Options{BaseURL: backend.URL, CarveDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan *mcplib.CallToolResult, 1)
			go func() {
				result, err := srv.mcpSrv.GetTool(name).Handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: map[string]any{
					"session_id": "/owned.pcap", "host": "192.0.2.1", "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
					"src_port": "52123", "dst_port": "443", "protocol": "TCP",
				}}})
				if err != nil {
					t.Errorf("tool call: %v", err)
				}
				done <- result
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("backend did not start sending data")
			}
			cancel()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Error("backend did not observe cancellation")
				return
			}
			select {
			case result := <-done:
				if result == nil || !result.IsError || !strings.Contains(contentText(result), "context canceled") {
					t.Fatalf("expected cancellation result, got %+v", result)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("tool did not return after cancellation")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("canceled carve published files: %v, %v", entries, err)
			}
		})
	}
}

func TestCarveForwardsTransportAndExactCaptureTime(t *testing.T) {
	for _, tc := range []struct{ tool, protocol, want string }{
		{"carve_subpcap_for_connection", "TCP", "TCP"},
		{"carve_subpcap_for_connection", "udp", "UDP"},
		{"carve_subpcap_for_connection", "", ""},
		{"carve_subpcap_for_connection", "ICMP", ""},
		{"carve_subpcap_for_certificate", "", "TCP"},
		{"carve_subpcap_for_http_pair", "", "TCP"},
	} {
		t.Run(tc.tool+tc.protocol, func(t *testing.T) {
			var calls atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				q := r.URL.Query()
				if q.Get("maxOutputBytes") != strconv.Itoa(maxBackendResponseBytes) {
					t.Errorf("missing backend output limit: %s", q.Encode())
				}
				if q.Get("protocol") != tc.want || q.Get("srcPort") != "52123" || q.Get("dstPort") != "443" || q.Get("startNs") != "1700000000000000001" || q.Get("endNs") != "1700000000000000003" || q.Get("inputFile") != "/owned.pcap" {
					t.Errorf("incorrect upstream selection: %s", q.Encode())
				}
				w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
				_, _ = w.Write([]byte("owned fixture bytes"))
			}))
			defer backend.Close()
			srv, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			tool := srv.mcpSrv.GetTool(tc.tool)
			if tool == nil {
				t.Fatal("missing carve tool")
			}
			result, err := tool.Handler(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: tc.tool, Arguments: map[string]any{
				"session_id": "/owned.pcap", "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "src_port": "52123", "dst_port": "443", "protocol": tc.protocol,
				"start_ns": "1700000000000000001", "end_ns": "1700000000000000003",
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError != (tc.want == "") {
				t.Fatalf("unexpected result: %s", contentText(result))
			}
			if want := int32(1); tc.want == "" {
				if calls.Load() != 0 {
					t.Fatal("invalid selector reached backend")
				}
			} else if calls.Load() != want {
				t.Fatalf("requests=%d", calls.Load())
			}
		})
	}
}
