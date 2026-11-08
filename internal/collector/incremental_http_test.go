package collector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	filedecoder "github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	httpdecoder "github.com/dreadl0ck/netcap/internal/decoder/stream/http"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"
)

func readIncrementalHTTP(t *testing.T, out string) []*types.HTTP {
	t.Helper()
	r, err := netio.Open(filepath.Join(out, "HTTP.ncap"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var rows []*types.HTTP
	for {
		record := new(types.HTTP)
		if err := r.Next(record); err == io.EOF {
			return rows
		} else if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, record)
	}
}

func TestIncrementalHTTPLiveKeepaliveBeforeClose(t *testing.T) {
	iface := loopbackInterface(t)
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var opened, closed, observed atomic.Int64
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "0")
				w.WriteHeader(404)
			}), ConnState: func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					opened.Add(1)
				}
				if state == http.StateClosed {
					closed.Add(1)
				}
			}}
			go server.Serve(listener)
			defer server.Close()
			out := t.TempDir()
			cfg := liveCaptureConfig(out, workers)
			cfg.NetworkDetection, cfg.CaptureEvidence = true, true
			cfg.LiveMaintenanceInterval, cfg.LiveFlushInterval = 50*time.Millisecond, 0
			cfg.DecoderConfig.IncrementalHTTP = true
			cfg.DecoderConfig.MaxRetainedTCPStateBytes = 1 << 20
			cfg.DecoderConfig.MaxRetainedTCPBytes = 1 << 16
			cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
			cfg.DecoderConfig.RecordObserver = func(m proto.Message) {
				if _, ok := m.(*types.HTTP); ok {
					observed.Add(1)
				}
			}
			c := New(cfg)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- c.CollectLive(iface, fmt.Sprintf("tcp port %d", listener.Addr().(*net.TCPAddr).Port), ctx)
			}()
			stopped := false
			defer func() {
				cancel()
				if !stopped {
					<-done
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				c.lifecycleMu.Lock()
				initialized := c.initialized
				c.lifecycleMu.Unlock()
				if initialized {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("live capture did not initialize")
				}
				time.Sleep(10 * time.Millisecond)
			}
			transport := &http.Transport{MaxConnsPerHost: 1, DisableCompression: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for i := 0; i < 40; i++ {
				response, err := client.Get(fmt.Sprintf("http://%s/missing/%d", listener.Addr(), i))
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			for observed.Load() < 40 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if observed.Load() != 40 || opened.Load() != 1 || closed.Load() != 0 {
				t.Fatalf("no before-close transactions: observed=%d connections=%d closed=%d", observed.Load(), opened.Load(), closed.Load())
			}
			c.flushAllDecoders()
			rows := readIncrementalHTTP(t, out)
			if len(rows) != 40 {
				t.Fatal("HTTP file still waits for close", len(rows))
			}
			alerts := readApplicationAlerts(t, c)
			scan := false
			for _, alert := range alerts {
				scan = scan || alert.Name == "http.scan"
			}
			if !scan {
				t.Fatal("qualified keepalive scan did not alert before close", alerts)
			}
			if h := c.streamStateBudget.Health(); h.RetainedBytes > 16<<10 || h.PeakBytes > h.LimitBytes {
				t.Fatal("completed transactions accumulated", h)
			}
			if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); !os.IsNotExist(err) {
				t.Fatal("active capture became audit-ready", err)
			}
			cancel()
			if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			stopped = true
			if rows = readIncrementalHTTP(t, out); len(rows) != 40 {
				t.Fatal("close duplicated already-emitted transactions", len(rows))
			}
			h := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
			if h.RetainedBytes != 0 || h.Exceeded {
				t.Fatal(h)
			}
			health := bookJSON[tcp.IncrementalHealth](t, filepath.Join(out, "TCPIncrementalHealth.json"))
			if health.IncrementalStreams != 1 || health.CompletedTransactions != 40 {
				t.Fatal(health)
			}
		})
	}
}

func TestIncrementalHTTPSharedStateBudgetsAndReadiness(t *testing.T) {
	for _, workers := range []int{1, 4} {
		for _, limit := range []int64{1000, 6000, 64 << 10, 1 << 20} {
			t.Run(fmt.Sprintf("workers=%d/limit=%d", workers, limit), func(t *testing.T) {
				wire, input := newBookCapture(t)
				for i := range 4 {
					send := wire.openTCP(fmt.Sprintf("192.0.2.%d", i+1), "198.51.100.1", uint16(40000+i), 80, false)
					send(false, false, false, "POST /pending HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 100000\r\n\r\n"+strings.Repeat("x", 16384))
				}
				out := t.TempDir()
				cfg := ultimateCaptureConfig(out, workers, 0)
				cfg.CaptureEvidence = true
				cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
				cfg.DecoderConfig.IncrementalHTTP = true
				cfg.DecoderConfig.MaxRetainedTCPStateBytes = limit
				c := New(cfg)
				err := c.CollectPcap(input)
				health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
				manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
				if health.RetainedBytes != 0 || health.PeakBytes > limit || manifest.Config.MaxRetainedTCPStateBytes != limit || !manifest.Config.IncrementalHTTP {
					t.Fatal(health, manifest.Config)
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if limit < 1<<20 {
					if !errors.Is(err, core.ErrStreamStateBudget) || manifest.Status != "error" || !health.Exceeded || !os.IsNotExist(readyErr) {
						t.Fatal("shared state exhaustion became ready", err, health, manifest.Status, readyErr)
					}
				} else {
					if err != nil || manifest.Status != "done" || health.Exceeded || readyErr != nil {
						t.Fatal(err, health, manifest.Status, readyErr)
					}
					if rows := readIncrementalHTTP(t, out); len(rows) != 4 {
						t.Fatal("EOF lost partial request evidence", rows)
					}
				}
			})
		}
	}
}

func TestIncrementalHTTPConversationPersistenceDoesNotReplayTransactions(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 40000, 80, false)
	for i := range 3 {
		send(false, false, false, fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: fixture.test\r\n\r\n", i))
		send(true, false, false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}
	for _, workers := range []int{1, 4} {
		out := t.TempDir()
		cfg := ultimateCaptureConfig(out, workers, 0)
		cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
		cfg.DecoderConfig.IncrementalHTTP, cfg.DecoderConfig.SaveConns = true, true
		cfg.DecoderConfig.MaxRetainedTCPStateBytes = 1 << 20
		if err := New(cfg).CollectPcap(input); err != nil {
			t.Fatal(err)
		}
		if rows := readIncrementalHTTP(t, out); len(rows) != 3 {
			t.Fatal("persistence replayed transactions", rows)
		}
		paths, _ := filepath.Glob(filepath.Join(out, "stream-evidence", "stream-*", "client.bin"))
		if len(paths) != 1 {
			t.Fatal("conversation was not persisted", paths)
		}
		data, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), "GET /") != 3 {
			t.Fatal("retirement truncated persisted conversation", string(data))
		}
	}
}

type incrementalHTTPFailWriter struct {
	netio.AuditRecordWriter
	err error
}

func (w incrementalHTTPFailWriter) Write(proto.Message) error { return w.err }

func TestIncrementalHTTPWriteFailurePreventsReadiness(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 40000, 80, false)
	send(false, false, false, "GET /owned HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	send(true, false, false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	send(false, false, false, "GET /write-fails HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	send(true, false, false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
	cfg.DecoderConfig.IncrementalHTTP = true
	cfg.DecoderConfig.MaxRetainedTCPStateBytes = 1 << 20
	failure := errors.New("injected incremental HTTP write failure")
	wrapped := false
	cfg.DecoderConfig.RecordObserver = func(m proto.Message) {
		if _, ok := m.(*types.HTTP); ok && !wrapped {
			httpdecoder.Decoder.Writer = incrementalHTTPFailWriter{AuditRecordWriter: httpdecoder.Decoder.Writer, err: failure}
			wrapped = true
		}
	}
	err := New(cfg).CollectPcap(input)
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
	if !wrapped || !errors.Is(err, failure) || manifest.Status != "error" || !os.IsNotExist(readyErr) {
		t.Fatal("failed HTTP record became ready", err, manifest.Status, readyErr)
	}
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if health.RetainedBytes != 0 || health.Exceeded {
		t.Fatal("I/O failure leaked or became a budget failure", health)
	}
}

func TestIncrementalHTTPMissingHandshakeIsExplicitlyCompletionOnly(t *testing.T) {
	wire, input := newBookCapture(t)
	request := "GET /midstream HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
	wire.packet("192.0.2.1", "198.51.100.1", &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 1001, Ack: 5001, ACK: true, Window: 65535}, request, false)
	wire.packet("198.51.100.1", "192.0.2.1", &layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 5001, Ack: uint32(1001 + len(request)), ACK: true, Window: 65535}, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false)
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 4, 0)
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
	cfg.DecoderConfig.IncrementalHTTP = true
	cfg.DecoderConfig.MaxRetainedTCPStateBytes = 1 << 20
	if err := New(cfg).CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	rows := readIncrementalHTTP(t, out)
	if len(rows) != 1 || !strings.Contains(rows[0].ReassemblyStatus, "unknown-initial-stream-loss") {
		t.Fatal("missing handshake became complete evidence", rows)
	}
	health := bookJSON[tcp.IncrementalHealth](t, filepath.Join(out, "TCPIncrementalHealth.json"))
	if health.IncrementalStreams != 0 || health.CompletionOnly["HTTP"] != 1 {
		t.Fatal("completion-only flow advertised incremental support", health)
	}
}

func TestIncrementalHTTPFileHashesAndExactStreamLoss(t *testing.T) {
	previous := filedecoder.GetGlobalConfig()
	filedecoder.SetGlobalConfig(filedecoder.GetDefaultConfig())
	defer filedecoder.SetGlobalConfig(previous)
	wire, input := newBookCapture(t)
	clean := wire.openTCP("192.0.2.1", "198.51.100.1", 40000, 80, false)
	clean(false, false, false, "GET /clean.bin HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	clean(true, false, false, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\nclean")
	gap := wire.openTCP("192.0.2.2", "198.51.100.1", 40001, 80, false)
	request := "GET /gap.bin HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
	gap(false, false, false, request)
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 6\r\n\r\nab"
	gap(true, false, false, response)
	wire.packet("198.51.100.1", "192.0.2.2", &layers.TCP{SrcPort: 80, DstPort: 40001, Seq: uint32(5001 + len(response) + 12), Ack: uint32(1001 + len(request)), ACK: true, Window: 65535}, "cd", false)
	for _, workers := range []int{1, 4} {
		out := t.TempDir()
		cfg := ultimateCaptureConfig(out, workers, 0)
		cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP,File"
		cfg.DecoderConfig.IncrementalHTTP = true
		cfg.DecoderConfig.MaxRetainedTCPStateBytes = 1 << 20
		cfg.DecoderConfig.FileStorage = "files"
		cfg.DecoderConfig.WriteIncomplete = true
		if err := New(cfg).CollectPcap(input); err != nil {
			t.Fatal(err)
		}
		r, err := netio.Open(filepath.Join(out, "File.ncap"), 4096)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadHeader(); err != nil {
			t.Fatal(err)
		}
		seenClean, seenGap := false, false
		for {
			row := new(types.File)
			if err := r.Next(row); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if row.Hashes != nil && row.Hashes.SHA256 == fmt.Sprintf("%x", sha256.Sum256([]byte("clean"))) {
				if !row.IsComplete || row.StreamMissingBytes != 0 || row.Length != 5 {
					t.Fatal("complete transaction file lost parity", row)
				}
				seenClean = true
			}
			if row.Length == 2 {
				if row.IsComplete || row.StreamMissingBytes != 12 || row.StreamInitialLossUnknown {
					t.Fatal("known sequence loss was invented or erased", row)
				}
				seenGap = true
			}
		}
		r.Close()
		if !seenClean || !seenGap {
			t.Fatal("missing complete/qualified extraction witnesses", seenClean, seenGap)
		}
	}
}
