package collector

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func TestTCPRetainedPayloadBudgetQualifiesFailureAndReadiness(t *testing.T) {
	for _, workers := range []int{1, 2, 4, 8} {
		for _, limit := range []int64{96, 256} {
			t.Run(fmt.Sprintf("workers=%d/limit=%d", workers, limit), func(t *testing.T) {
				wire, input := newBookCapture(t)
				for index := range 4 {
					send := wire.openTCP(fmt.Sprintf("192.0.2.%d", index+1), "198.51.100.1", uint16(45000+index), 65000, false)
					send(false, false, false, string(bytes.Repeat([]byte{0xff}, 64)))
				}
				out := t.TempDir()
				configuration := ultimateCaptureConfig(out, workers, 0)
				configuration.CaptureEvidence = true
				configuration.DecoderConfig.IncludeDecoders = "TCP,Connection"
				configuration.DecoderConfig.MaxRetainedTCPBytes = limit
				configuration.DecoderConfig.SaveConns = true
				collector := New(configuration)
				err := collector.CollectPcap(input)
				health := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(out, "TCPReassemblyHealth.json"))
				if health.RetainedPayload == nil || health.RetainedPayload.LimitBytes != limit || health.RetainedPayload.PeakBytes > limit || health.RetainedPayload.RetainedBytes != 0 {
					t.Fatalf("invalid shared budget health: %+v", health.RetainedPayload)
				}
				manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
				streams, globErr := filepath.Glob(filepath.Join(out, "stream-evidence", "stream-*", "manifest.json"))
				if globErr != nil {
					t.Fatal(globErr)
				}
				var discarded int64
				for _, path := range streams {
					stream := bookJSON[streamutils.StreamEvidenceManifest](t, path)
					for _, span := range stream.Spans {
						if span.DiscardedBytes > 0 {
							if stream.Status != "locally-truncated" || span.MissingBytes != 0 || span.DiscardReason != "tcp-retained-payload-budget" {
								t.Fatalf("local omission became a network gap or clean stream: %+v", stream)
							}
							discarded += span.DiscardedBytes
						}
					}
				}
				if discarded != health.RetainedPayload.RejectedBytes {
					t.Fatalf("per-stream discard evidence lost: spans=%d health=%d", discarded, health.RetainedPayload.RejectedBytes)
				}
				if manifest.Config.MaxRetainedTCPBytes != limit {
					t.Fatal("effective retention budget missing from capture configuration")
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if limit == 96 {
					if !errors.Is(err, tcp.ErrRetainedPayloadLimit) || manifest.Status != "error" || !strings.Contains(manifest.Error, "retained payload budget exceeded") || !os.IsNotExist(readyErr) || !health.RetainedPayload.Exceeded || health.RetainedPayload.RejectedBytes == 0 {
						t.Fatalf("overflow became successful output: err=%v manifest=%+v health=%+v ready=%v", err, manifest, health.RetainedPayload, readyErr)
					}
				} else {
					if err != nil || manifest.Status != "done" || readyErr != nil || health.RetainedPayload.Exceeded || health.RetainedPayload.PeakBytes < 64 || manifest.AdmittedPackets != uint64(wire.n) {
						t.Fatalf("under-budget capture failed: err=%v manifest=%+v health=%+v ready=%v", err, manifest, health.RetainedPayload, readyErr)
					}
				}
			})
		}
	}
}

func TestLocalRetainedPayloadLossPreservesUnrelatedHTTP(t *testing.T) {
	for _, backed := range []bool{false, true} {
		t.Run(fmt.Sprint(backed), func(t *testing.T) {
			wire, input := newBookCapture(t)
			wire.conversation("192.0.2.1", "198.51.100.1", 45000, 80, false, bookMessage{text: "GET /affected HTTP/1.1\r\nHost: fixture.test\r\nX-Large: " + strings.Repeat("x", 1024) + "\r\n\r\n"})
			wire.conversation("192.0.2.2", "198.51.100.1", 45001, 80, false, bookMessage{text: "GET /healthy HTTP/1.1\r\nHost: fixture.test\r\n\r\n"}, bookMessage{server: true, text: "HTTP/1.1 204 No Content\r\n\r\n"})
			out := t.TempDir()
			cfg := ultimateCaptureConfig(out, 1, 0)
			cfg.CaptureEvidence = true
			cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
			cfg.DecoderConfig.SaveConns = true
			cfg.DecoderConfig.MaxRetainedTCPBytes = 192
			cfg.DecoderConfig.LocalRetainedPayloadLoss = true
			if backed {
				cfg.DecoderConfig.MaxAggregateStateBytes = 1 << 20
			}
			err := New(cfg).CollectPcap(input)
			var partial *localReassemblyCoverageError
			if !errors.As(err, &partial) || !errors.Is(err, tcp.ErrRetainedPayloadLimit) {
				t.Fatal(err)
			}
			manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
			if manifest.Status != "partial" || manifest.Error != "" || manifest.AdmittedPackets != uint64(wire.n) {
				t.Fatal(manifest.Status, manifest.Error, manifest.AdmittedPackets, wire.n)
			}
			records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			if len(records) != 1 || records[0].URL != "/healthy" || records[0].StatusCode != 204 {
				t.Fatal(records)
			}
			health := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(out, "TCPReassemblyHealth.json")).RetainedPayload
			if health == nil || !health.Exceeded || health.RetainedBytes != 0 || health.PeakBytes > health.LimitBytes {
				t.Fatal(health)
			}
		})
	}
}

func TestLocalCompletionStateLossPreservesUnrelatedHTTP(t *testing.T) {
	wire, input := newBookCapture(t)
	affected := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 80, false)
	for range 128 {
		affected(false, false, false, "GET /affected HTTP/1.1\r\nHost: fixture.test\r\nX-Label: "+strings.Repeat("x", 512)+"\r\n\r\n")
	}
	wire.conversation("192.0.2.2", "198.51.100.1", 45001, 80, false,
		bookMessage{text: "GET /healthy HTTP/1.1\r\nHost: fixture.test\r\n\r\n"},
		bookMessage{server: true, text: "HTTP/1.1 204 No Content\r\n\r\n"})
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
	cfg.DecoderConfig.MaxAggregateStateBytes = 1 << 20
	cfg.DecoderConfig.MaxRetainedTCPStateBytes = 128 << 10
	cfg.DecoderConfig.LocalCompletionStateLoss = true
	err := New(cfg).CollectPcap(input)
	var partial *localReassemblyCoverageError
	if !errors.As(err, &partial) || !errors.Is(err, core.ErrCompletionStateBudget) {
		t.Fatal(err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "partial" || manifest.Error != "" || manifest.AdmittedPackets != uint64(wire.n) {
		t.Fatal(manifest)
	}
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if health.Exceeded || health.CompletionRejectedBytes == 0 || health.RetainedBytes != 0 || health.PeakBytes > health.LimitBytes {
		t.Fatal(health)
	}
	records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
	if len(records) != 1 || records[0].URL != "/healthy" || records[0].StatusCode != 204 {
		t.Fatalf("unexpected HTTP records: %d", len(records))
	}
}

func TestBackedSMTPCompletionUsesFragmentBudgets(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 25, false)
	send(true, false, false, "220 mail.example ESMTP ready\r\n")
	send(false, false, false, "EHLO client\r\n")
	chunk := strings.Repeat("NOOP\r\n", 128)
	for range 256 {
		send(false, false, false, chunk)
	}
	send(true, false, false, "250 accepted\r\n")
	out := t.TempDir()
	configuration := ultimateCaptureConfig(out, 1, 0)
	configuration.CaptureEvidence = true
	configuration.DecoderConfig.IncludeDecoders = "TCP,Connection,SMTP,TLSRecord,Secret"
	configuration.DecoderConfig.SaveConns = true
	configuration.DecoderConfig.MaxAggregateStateBytes = 1024
	configuration.DecoderConfig.MaxRetainedTCPStateBytes = 16384
	configuration.DecoderConfig.MaxRetainedTCPBytes = 4096
	if err := New(configuration).CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	if manifest.Status != "done" {
		t.Fatal("streaming completion was not sealed", manifest.Status)
	}
	if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); err != nil {
		t.Fatal(err)
	}
	records := bookRecords(t, out, "SMTP", func() *types.SMTP { return new(types.SMTP) })
	if len(records) != 1 || len(records[0].Commands) != 32769 {
		t.Fatal("streaming completion changed commands", len(records))
	}
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if health.Exceeded || health.RetainedBytes != 0 || health.PeakBytes > 16384 {
		t.Fatal("completion exceeded fragment credits", health)
	}
	t.Logf("client command bytes=%d state peak=%d limit=%d", len(chunk)*256, health.PeakBytes, health.LimitBytes)
}

func TestBackedTLSRecordsAndUpgradeStayWithinFragmentBudgets(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprint("upgrade=", upgrade), func(t *testing.T) {
			wire, input := newBookCapture(t)
			port := uint16(443)
			if upgrade {
				port = 25
			}
			send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, port, false)
			if upgrade {
				send(true, false, false, "220 mail.example ESMTP ready\r\n")
				send(false, false, false, "EHLO client\r\n")
				send(true, false, false, "250 ready\r\n")
				send(false, false, false, "STARTTLS\r\n")
				send(true, false, false, "220 ready\r\n")
			}
			body := append([]byte{3, 3}, make([]byte, 32)...)
			body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
			handshake := append([]byte{1, 0, 0, byte(len(body))}, body...)
			hello := append([]byte{22, 3, 3, 0, byte(len(handshake))}, handshake...)
			send(false, false, false, string(hello))
			record := append([]byte{23, 3, 3, 4, 0}, bytes.Repeat([]byte{0x80}, 1024)...)
			for range 512 {
				send(false, false, false, string(record))
			}
			out := t.TempDir()
			configuration := ultimateCaptureConfig(out, 4, 0)
			configuration.CaptureEvidence = true
			configuration.DecoderConfig.IncludeDecoders = "TCP,Connection,TLSRecord,TLSClientHello,SMTP"
			configuration.DecoderConfig.SaveConns = true
			configuration.DecoderConfig.MaxAggregateStateBytes = 1024
			configuration.DecoderConfig.MaxRetainedTCPStateBytes = 65536
			configuration.DecoderConfig.MaxRetainedTCPBytes = 8192
			if err := New(configuration).CollectPcap(input); err != nil {
				t.Fatal(err)
			}
			records := bookRecords(t, out, "TLSRecord", func() *types.TLSRecord { return new(types.TLSRecord) })
			if len(records) != 513 {
				t.Fatal("TLS source lost records", len(records))
			}
			for _, record := range records {
				if record.Status != "complete" {
					t.Fatal("TLS source changed record framing", record)
				}
			}
			hellos := bookRecords(t, out, "TLSClientHello", func() *types.TLSClientHello { return new(types.TLSClientHello) })
			if len(hellos) != 1 {
				t.Fatal("TLS source lost client hello", len(hellos))
			}
			if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); err != nil {
				t.Fatal(err)
			}
			health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
			if health.Exceeded || health.RetainedBytes != 0 || health.PeakBytes > 65536 {
				t.Fatal("TLS source leaked state credits", health)
			}
			t.Logf("TLS payload bytes=%d peak state credits=%d", len(record)*512+len(hello), health.PeakBytes)
		})
	}
}

func TestBackedHTTPPassiveLargeBodyUsesBoundedInput(t *testing.T) {
	testBackedHTTPLargeBody(t, false)
}

func TestBackedHTTPExtractionLargeBodyUsesBoundedInput(t *testing.T) {
	testBackedHTTPLargeBody(t, true)
}

func testBackedHTTPLargeBody(t *testing.T, extract bool) {
	t.Helper()
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 80, false)
	send(false, false, false, "GET /large.bin HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	const size = 90 << 20
	send(true, false, false, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", size))
	chunk := strings.Repeat("x", 32768)
	for range size / len(chunk) {
		send(true, false, false, chunk)
	}
	out := t.TempDir()
	configuration := ultimateCaptureConfig(out, 1, 0)
	configuration.CaptureEvidence = true
	configuration.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP,IPP"
	if extract {
		configuration.DecoderConfig.IncludeDecoders += ",File"
		configuration.DecoderConfig.FileStorage = "files"
		old := file.GetGlobalConfig()
		cfg := file.GetDefaultConfig()
		cfg.FileExtraction.SizeLimits.MaxInflightBytes = 1 << 20
		file.SetGlobalConfig(cfg)
		t.Cleanup(func() { file.SetGlobalConfig(old) })
	}
	configuration.DecoderConfig.MaxAggregateStateBytes = 65536
	configuration.DecoderConfig.MaxRetainedTCPStateBytes = 262144
	configuration.DecoderConfig.MaxRetainedTCPBytes = 131072
	if err := New(configuration).CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
	if len(records) != 1 || records[0].Method != "GET" || records[0].StatusCode != 200 || records[0].ResContentLength != size || records[0].ReassemblyStatus != "" {
		t.Fatal("streaming HTTP changed the visible transaction", records)
	}
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if health.Exceeded || health.RetainedBytes != 0 || health.PeakBytes > 262144 {
		t.Fatal("large HTTP body exceeded input credits", health)
	}
	if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); err != nil {
		t.Fatal(err)
	}
	if extract {
		files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
		if len(files) != 1 || files[0].Length != size || !files[0].IsComplete {
			t.Fatal("large extracted body missing or incomplete", files)
		}
		hashes, err := file.ComputeFileHashes(files[0].Location)
		if err != nil || hashes.SHA256 != files[0].Hashes.SHA256 {
			t.Fatal("large artifact hash mismatch", err)
		}
		entries, err := os.ReadDir(filepath.Join(out, ".artifact-scratch"))
		if err != nil || len(entries) != 0 {
			t.Fatal("artifact scratch was not cleaned", entries, err)
		}
	}
	t.Logf("HTTP body bytes=%d peak input/state credits=%d", size, health.PeakBytes)
}

func TestBackedHTTPPassiveUploadUsesBoundedInput(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 80, false)
	const size = 3 << 20
	send(false, false, false, fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", size))
	chunk := strings.Repeat("x", 16384)
	for range size / len(chunk) {
		send(false, false, false, chunk)
	}
	send(true, false, false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	out := t.TempDir()
	configuration := ultimateCaptureConfig(out, 1, 0)
	configuration.CaptureEvidence = true
	configuration.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP,IPP"
	configuration.DecoderConfig.MaxAggregateStateBytes = 65536
	configuration.DecoderConfig.MaxRetainedTCPStateBytes = 262144
	configuration.DecoderConfig.MaxRetainedTCPBytes = 131072
	if err := New(configuration).CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
	if len(records) != 1 || records[0].Method != "POST" || records[0].ReqContentLength != size || records[0].StatusCode != 200 || records[0].ReassemblyStatus != "" {
		t.Fatal("opaque upload changed visible metadata", records)
	}
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if health.Exceeded || health.RetainedBytes != 0 || health.PeakBytes > 262144 {
		t.Fatal("opaque upload exceeded input credits", health)
	}
	if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); err != nil {
		t.Fatal(err)
	}
	t.Logf("HTTP upload bytes=%d peak input/state credits=%d", size, health.PeakBytes)
}

func TestBackedHTTPGzipPressurePreservesSpooledResponse(t *testing.T) {
	testBackedHTTPGzipPressurePreservesSpool(t, false)
}

func TestBackedHTTPGzipPressurePreservesSpooledRequest(t *testing.T) {
	testBackedHTTPGzipPressurePreservesSpool(t, true)
}

func testBackedHTTPGzipPressurePreservesSpool(t *testing.T, upload bool) {
	t.Helper()
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 80, false)
	body := strings.Repeat("fixture response\n", 1024)
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	entity := fmt.Sprintf("Content-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", compressed.Len(), compressed.Bytes())
	wantDirection := "server_to_client"
	if upload {
		wantDirection = "client_to_server"
		send(false, false, false, "POST /fixture.txt HTTP/1.1\r\nHost: fixture.test\r\n"+entity)
		send(true, false, false, "HTTP/1.1 204 No Content\r\n\r\n")
	} else {
		send(false, false, false, "GET /fixture.txt HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
		send(true, false, false, "HTTP/1.1 200 OK\r\n"+entity)
	}
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP,File"
	cfg.DecoderConfig.FileStorage = "files"
	cfg.DecoderConfig.MaxRetainedTCPStateBytes = 64 << 10
	cfg.DecoderConfig.LocalCompletionStateLoss = true
	err := New(cfg).CollectPcap(input)
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
	if !errors.Is(err, core.ErrCompletionStateBudget) || manifest.Status != "partial" || health.Exceeded || health.RetainedBytes != 0 || health.CompletionRejectedBytes != 65536 {
		t.Fatalf("gzip probe pressure: status=%s err=%v budget=%+v", manifest.Status, err, health)
	}
	files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
	if len(files) != 1 || !files[0].IsComplete || files[0].Length != int64(len(body)) || files[0].FlowDirection != wantDirection || files[0].Hashes.GetSHA256() != file.ComputeHashes([]byte(body)).SHA256 {
		t.Fatalf("decoded artifact lost: %v", files)
	}
	hashes, err := file.ComputeFileHashes(files[0].Location)
	if err != nil || hashes.SHA256 != files[0].Hashes.GetSHA256() {
		t.Fatalf("response artifact hash mismatch: %v", err)
	}
}

func TestBackedHTTPFormPressurePreservesSpooledArtifact(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 80, false)
	body := strings.Repeat("data=fixture&", 2048) + "tail=done"
	send(false, false, false, fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n", len(body)))
	for off := 0; off < len(body); off += 8192 {
		send(false, false, false, body[off:min(off+8192, len(body))])
	}
	send(true, false, false, "HTTP/1.1 204 No Content\r\n\r\n")
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
			out := t.TempDir()
			cfg := ultimateCaptureConfig(out, 1, 0)
			cfg.CaptureEvidence = true
			cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP,File"
			cfg.DecoderConfig.FileStorage = "files"
			cfg.DecoderConfig.MaxRetainedTCPBytes = 128 << 10
			cfg.DecoderConfig.MaxRetainedTCPStateBytes = 256 << 10
			cfg.DecoderConfig.LocalCompletionStateLoss = local
			err := New(cfg).CollectPcap(input)
			manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
			health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
			if health.Exceeded == local || health.RetainedBytes != 0 {
				t.Fatalf("unexpected state budget: %+v", health)
			}
			if !local {
				if !errors.Is(err, core.ErrStreamStateBudget) || manifest.Status != "error" {
					t.Fatalf("strict replay: status=%s err=%v", manifest.Status, err)
				}
				return
			}
			if !errors.Is(err, core.ErrCompletionStateBudget) || manifest.Status != "partial" || health.CompletionRejectedBytes == 0 {
				t.Fatalf("local replay: status=%s err=%v budget=%+v", manifest.Status, err, health)
			}
			t.Logf("completion pressure: %v; %+v", err, health)
			files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
			if len(files) != 1 || !files[0].IsComplete || files[0].Length != int64(len(body)) {
				t.Fatalf("spooled request artifact lost: %v", files)
			}
			hashes, err := file.ComputeFileHashes(files[0].Location)
			if err != nil || hashes.SHA256 != file.ComputeHashes([]byte(body)).SHA256 || files[0].Hashes.GetSHA256() != hashes.SHA256 {
				t.Fatalf("spooled artifact hash mismatch: %v", err)
			}
		})
	}
}

func TestNegativeTCPRetentionBudgetRefusesInitialization(t *testing.T) {
	configuration := ultimateCaptureConfig(t.TempDir(), 1, 0)
	configuration.DecoderConfig.MaxRetainedTCPBytes = -1
	collector := New(configuration)
	defer collector.Stop()
	if err := collector.Init(); err == nil || !strings.Contains(err.Error(), "cannot be negative") {
		t.Fatalf("negative budget accepted: %v", err)
	}
	if collector.initialized || len(collector.workers) != 0 {
		t.Fatal("invalid budget started workers")
	}
}

func TestBackedTCPMaterializationFailurePreventsReadiness(t *testing.T) {
	for _, mode := range []string{"payload", "state", "local-state"} {
		t.Run(mode, func(t *testing.T) {
			wire, input := newBookCapture(t)
			send := wire.openTCP("192.0.2.1", "198.51.100.1", 45000, 65000, false)
			for range 4 {
				send(false, false, false, string(bytes.Repeat([]byte{0xff}, 8192)))
			}
			out := t.TempDir()
			configuration := ultimateCaptureConfig(out, 1, 0)
			configuration.CaptureEvidence = true
			configuration.DecoderConfig.IncludeDecoders = "TCP,Connection"
			configuration.DecoderConfig.MaxAggregateStateBytes = 1024
			if mode == "payload" {
				configuration.DecoderConfig.MaxRetainedTCPBytes = 16384
			} else {
				configuration.DecoderConfig.MaxRetainedTCPStateBytes = 16384
				configuration.DecoderConfig.LocalCompletionStateLoss = mode == "local-state"
			}
			err := New(configuration).CollectPcap(input)
			manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
			_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
			wantStatus := "error"
			if mode == "local-state" {
				wantStatus = "partial"
				var partial *localReassemblyCoverageError
				if !errors.As(err, &partial) || !errors.Is(err, core.ErrCompletionStateBudget) || manifest.Error != "" || manifest.AdmittedPackets != uint64(wire.n) {
					t.Fatalf("local failure lost coverage or admission: %v, %+v", err, manifest)
				}
				health := bookJSON[core.StateBudgetHealth](t, filepath.Join(out, "TCPStreamStateBudget.json"))
				if health.Exceeded || health.CompletionRejectedBytes == 0 || health.RetainedBytes != 0 || health.PeakBytes > health.LimitBytes {
					t.Fatal(health)
				}
			}
			if err == nil || manifest.Status != wantStatus || !os.IsNotExist(readyErr) {
				t.Fatalf("backing materialization failure advertised success: err=%v manifest=%+v ready=%v", err, manifest, readyErr)
			}
			if !errors.Is(err, tcp.ErrRetainedPayloadLimit) && !strings.Contains(err.Error(), "materialization") && !strings.Contains(err.Error(), "stream state budget exceeded") {
				t.Fatal("unexpected capture failure", err)
			}
			connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
			if len(connections) != 1 {
				t.Fatal("materialization failure lost independent connection output", len(connections))
			}
		})
	}
}
