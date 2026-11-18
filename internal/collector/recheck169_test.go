package collector

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestRecheckArchiveDefaultCompatibility(t *testing.T) {
	path := os.Getenv("NETCAP_RECHECK_ARCHIVE")
	if path == "" {
		t.Skip("set NETCAP_RECHECK_ARCHIVE to the pinned synthetic regression archive")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != "6e061856cdc2e363e2494757b4be70abe9f1671cdff5270d403f488f9ba2446f" {
		t.Fatal("regression archive digest changed")
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, name := range []string{"dns_query_fp.pcap", "dns_response_fp.pcap", "nbns_query_fp.pcap", "nbns_refresh_fp.pcap", "v169_midstream_psh_15k.pcap", "v168_udp_uniqflows_50k.pcap"} {
		t.Run(name, func(t *testing.T) {
			member := "netcap-v0.16.9-synthetic-repros/repro/v169/edge/" + name
			reader, err := archive.Open(member)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(reader, 8<<20))
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			if name == "v168_udp_uniqflows_50k.pcap" {
				checkRecheckUDPSpill(t, input)
				return
			}
			out := t.TempDir()
			configuration := ultimateCaptureConfig(out, 1, 0)
			configuration.DecoderConfig.MaxRetainedTCPBytes = defaults.MaxRetainedTCPBytes
			configuration.DecoderConfig.MaxRetainedReassemblyBytes = defaults.MaxRetainedReassemblyBytes
			configuration.DecoderConfig.MaxRetainedTCPStateBytes = defaults.MaxRetainedTCPStateBytes
			configuration.DecoderConfig.MaxAggregateStateBytes = defaults.MaxAggregateStateBytes
			configuration.DecoderConfig.IncludeDecoders = ""
			if err := New(configuration).CollectPcap(input); err != nil {
				t.Fatal(err)
			}
			if name == "v169_midstream_psh_15k.pcap" {
				connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
				if len(connections) != 15000 {
					t.Fatal("default capture lost connections", len(connections))
				}
				checkStrictFinite := func(t *testing.T, workers int, export bool) {
					finiteOut := t.TempDir()
					cfg := ultimateCaptureConfig(finiteOut, workers, 0)
					cfg.CaptureEvidence = true
					cfg.DecoderConfig.MaxRetainedReassemblyBytes = 128 << 20
					cfg.DecoderConfig.MaxRetainedTCPStateBytes = 256 << 20
					cfg.DecoderConfig.MaxRetainedTCPBytes = 256 << 10
					cfg.DecoderConfig.MaxAggregateStateBytes = 1 << 20
					cfg.DecoderConfig.SaveConns = export
					stopSampling := sampleRecheckFootprint(finiteOut)
					start := time.Now()
					captureErr := New(cfg).CollectPcap(input)
					duration := time.Since(start)
					footprint := stopSampling()
					if err := errors.Join(captureErr, footprint.err); err != nil {
						t.Fatal(err)
					}
					t.Logf("output tree: sampled peak %d logical bytes; final %d logical bytes (%d samples)", footprint.peak, footprint.final, footprint.samples)
					if footprint.hasAllocation {
						t.Logf("output tree: sampled peak %d allocated bytes; final %d allocated bytes", footprint.peakAllocated, footprint.finalAllocated)
					}
					if workers == 4 {
						t.Logf("capture with export=%t completed in %s", export, duration)
					}
					if _, err := os.Stat(filepath.Join(finiteOut, evidence.AuditReadyFile)); err != nil {
						t.Fatal(err)
					}
					manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(finiteOut, "capture-manifest.json"))
					if manifest.Status != "done" || manifest.AdmittedPackets != 15000 {
						t.Fatalf("unexpected capture status %q or packet count %d", manifest.Status, manifest.AdmittedPackets)
					}
					for _, typ := range []string{"TCP", "Connection"} {
						stage, _, err := evidence.ReadAuditStage(finiteOut, manifest.RunID, typ, manifest.AuditStagesGeneration)
						if err != nil || stage.Coverage != "complete" || stage.Records != 15000 {
							t.Fatal(typ, stage, err)
						}
					}
					checkRecheckAuditMultiset(t, "Connection", 15000, connections, bookRecords(t, finiteOut, "Connection", func() *types.Connection { return new(types.Connection) }))
					checkRecheckAuditMultiset(t, "TCP", 15000, bookRecords(t, out, "TCP", func() *types.TCP { return new(types.TCP) }), bookRecords(t, finiteOut, "TCP", func() *types.TCP { return new(types.TCP) }))
					pages := bookJSON[reassembly.PageBudgetHealth](t, filepath.Join(finiteOut, "TCPReassemblyPageBudget.json"))
					state := bookJSON[core.StateBudgetHealth](t, filepath.Join(finiteOut, "TCPStreamStateBudget.json"))
					if pages.Exceeded || state.Exceeded || pages.RetainedBytes != 0 || state.RetainedBytes != 0 || pages.PeakBytes > pages.LimitBytes || state.PeakBytes > state.LimitBytes {
						t.Fatalf("unexpected budget state: pages=%+v state=%+v", pages, state)
					}
					cache := bookJSON[aggregate.Health](t, filepath.Join(finiteOut, "AggregateStateHealth.json"))
					if cache.LimitBytes != cfg.DecoderConfig.MaxAggregateStateBytes || cache.PeakBytes > cache.LimitBytes || cache.Evictions == 0 || cache.DiskWrites == 0 {
						t.Fatalf("aggregate spill was not exercised within the cap: %+v", cache)
					}
					if scratch, err := filepath.Glob(filepath.Join(finiteOut, ".netcap-aggregate-*")); err != nil || len(scratch) != 0 {
						t.Fatalf("aggregate scratch remained: %v, %v", scratch, err)
					}
					t.Logf("strict finite replay peaks: page bytes %d, TCP state bytes %d", pages.PeakBytes, state.PeakBytes)
					t.Logf("aggregate peak cache bytes %d; database bytes %d; evictions %d", cache.PeakBytes, cache.DatabaseBytes, cache.Evictions)
					if export {
						checkRecheckFanoutExports(t, input, finiteOut)
					}
				}
				t.Run("strict-finite-budgets", func(t *testing.T) { checkStrictFinite(t, 1, false) })
				t.Run("strict-finite-budgets-4-workers", func(t *testing.T) { checkStrictFinite(t, 4, false) })
				t.Run("strict-finite-budgets-export-4-workers", func(t *testing.T) {
					if os.Getenv("NETCAP_RECHECK_FANOUT_EXPORT") != "1" {
						t.Skip("set NETCAP_RECHECK_FANOUT_EXPORT=1 for conversation export")
					}
					checkStrictFinite(t, 4, true)
				})
				checkPagePressure := func(t *testing.T, workers int, saveConns bool) {
					out := t.TempDir()
					cfg := ultimateCaptureConfig(out, workers, 0)
					cfg.CaptureEvidence = true
					cfg.DecoderConfig.IncludeDecoders = "TCP,Connection"
					cfg.DecoderConfig.MaxRetainedReassemblyBytes = 2 << 20
					cfg.DecoderConfig.LocalReassemblyPageLoss = true
					cfg.DecoderConfig.SaveConns = saveConns
					err := New(cfg).CollectPcap(input)
					var partial *localReassemblyCoverageError
					if !errors.As(err, &partial) || partial.ExitCode() != 2 || !errors.Is(err, reassembly.ErrPageBudget) {
						t.Fatalf("expected partial page coverage: %v", err)
					}
					manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
					if manifest.Status != "partial" || manifest.AdmittedPackets != 15000 {
						t.Fatalf("unexpected capture status %q or packet count %d", manifest.Status, manifest.AdmittedPackets)
					}
					for typ, coverage := range map[string]string{"TCP": "complete", "Connection": "partial"} {
						stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, typ, manifest.AuditStagesGeneration)
						if err != nil || stage.Coverage != coverage || stage.Records != 15000 {
							t.Fatal(typ, stage, err)
						}
					}
					health := bookJSON[reassembly.PageBudgetHealth](t, filepath.Join(out, "TCPReassemblyPageBudget.json"))
					if !health.Exceeded || health.PeakBytes > health.LimitBytes || health.RetainedBytes != 0 {
						t.Fatal(health)
					}
					t.Logf("retained all packet and connection rows; page peak %d bytes", health.PeakBytes)
					if cfg.DecoderConfig.SaveConns {
						entries, err := os.ReadDir(filepath.Join(out, "stream-evidence"))
						if err != nil || len(entries) != 15000 {
							t.Fatalf("stream exports: got %d, want 15000: %v", len(entries), err)
						}
						for _, entry := range entries {
							if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "stream-") {
								t.Fatalf("unexpected export entry %s", entry.Name())
							}
						}
					}
				}
				t.Run("local-page-pressure", func(t *testing.T) {
					checkPagePressure(t, 1, os.Getenv("NETCAP_RECHECK_FANOUT_EXPORT") == "1")
				})
				t.Run("local-page-pressure-4-workers", func(t *testing.T) {
					checkPagePressure(t, 4, false)
				})
			} else if _, err := os.Stat(filepath.Join(out, "Protobuf.ncap.gz")); err == nil {
				records := bookRecords(t, out, "Protobuf", func() *types.Protobuf { return new(types.Protobuf) })
				if len(records) != 0 {
					t.Fatal("foreign traffic claimed ambiguous wire format", len(records))
				}
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}

func checkRecheckUDPSpill(t *testing.T, input string) {
	t.Helper()
	const rows = 50_000
	const finite = 1 << 20
	var baselineUDP []*types.UDP
	var baselineConnections []*types.Connection
	for _, limit := range []int64{0, finite} {
		out := t.TempDir()
		cfg := ultimateCaptureConfig(out, 4, 0)
		cfg.CaptureEvidence = true
		cfg.DecoderConfig.MaxRetainedReassemblyBytes = 128 << 20
		cfg.DecoderConfig.MaxRetainedTCPStateBytes = 256 << 20
		cfg.DecoderConfig.MaxRetainedTCPBytes = 256 << 10
		cfg.DecoderConfig.MaxAggregateStateBytes = limit
		if err := New(cfg).CollectPcap(input); err != nil {
			t.Fatal(err)
		}
		manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
		if manifest.Status != "done" || manifest.AdmittedPackets != rows {
			t.Fatalf("aggregate cap %d: status=%s admitted=%d", limit, manifest.Status, manifest.AdmittedPackets)
		}
		for _, typ := range []string{"UDP", "Connection"} {
			stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, typ, manifest.AuditStagesGeneration)
			if err != nil || stage.Coverage != "complete" || stage.Records != rows {
				t.Fatal(typ, stage, err)
			}
		}
		udp := bookRecords(t, out, "UDP", func() *types.UDP { return new(types.UDP) })
		connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
		if len(udp) != rows || len(connections) != rows {
			t.Fatalf("aggregate cap %d: UDP=%d Connection=%d", limit, len(udp), len(connections))
		}
		if limit == 0 {
			baselineUDP, baselineConnections = udp, connections
			continue
		}
		checkRecheckAuditMultiset(t, "UDP", rows, baselineUDP, udp)
		checkRecheckAuditMultiset(t, "Connection", rows, baselineConnections, connections)
		health := bookJSON[aggregate.Health](t, filepath.Join(out, "AggregateStateHealth.json"))
		if health.LimitBytes != finite || health.PeakBytes > finite || health.Evictions == 0 || health.DiskWrites == 0 {
			t.Fatalf("finite spill not exercised: %+v", health)
		}
		if scratch, err := filepath.Glob(filepath.Join(out, ".netcap-aggregate-*")); err != nil || len(scratch) != 0 {
			t.Fatalf("aggregate scratch remained: %v, %v", scratch, err)
		}
		t.Logf("matched both %d-row audit multisets; aggregate peak %d bytes, %d evictions, spill size %d bytes", rows, health.PeakBytes, health.Evictions, health.DatabaseBytes)
	}
}

type recheckFootprint struct {
	peak, final                   int64
	peakAllocated, finalAllocated int64
	hasAllocation                 bool
	samples                       int
	err                           error
}

func sampleRecheckFootprint(root string) func() recheckFootprint {
	stop := make(chan struct{})
	done := make(chan recheckFootprint, 1)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		result := recheckFootprint{hasAllocation: recheckAllocationAvailable}
		sample := func() {
			var size, allocated int64
			err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if errors.Is(err, fs.ErrNotExist) && path != root {
					return nil // Scratch files can disappear during the walk.
				}
				if err != nil || !entry.Type().IsRegular() {
					return err
				}
				info, err := entry.Info()
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				if err == nil {
					size += info.Size()
					if result.hasAllocation {
						bytes, ok := recheckAllocatedBytes(info)
						result.hasAllocation = ok
						allocated += bytes
					}
				}
				return err
			})
			if err != nil {
				result.err = err
				return
			}
			result.samples++
			result.final, result.peak = size, max(result.peak, size)
			result.finalAllocated, result.peakAllocated = allocated, max(result.peakAllocated, allocated)
		}
		for result.err == nil {
			select {
			case <-ticker.C:
				sample()
			case <-stop:
				sample()
				done <- result
				return
			}
		}
		done <- result
	}()
	return func() recheckFootprint {
		close(stop)
		return <-done
	}
}

func checkRecheckFanoutExports(t *testing.T, input, out string) {
	t.Helper()
	type packetKey struct {
		timestamp string
		digest    [sha256.Size]byte
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[packetKey]int)
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.NoCopy)
		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 {
			t.Fatal("expected one payload-bearing TCP packet per fixture flow")
		}
		want[packetKey{fmt.Sprint(ci.Timestamp.UnixNano()), sha256.Sum256(tcp.Payload)}]++
	}
	root := filepath.Join(out, "stream-evidence")
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 15000 {
		t.Fatalf("stream exports: got %d, want 15000: %v", len(entries), err)
	}
	got := make(map[packetKey]int)
	var payloadBytes int64
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "stream-") {
			t.Fatalf("unexpected export entry %s", entry.Name())
		}
		dir := filepath.Join(root, entry.Name())
		m := bookJSON[utils.StreamEvidenceManifest](t, filepath.Join(dir, "manifest.json"))
		if m.Protocol != "TCP" {
			t.Fatalf("unexpected protocol in %s: %s", dir, m.Protocol)
		}
		payloadSpans := 0
		for _, direction := range []struct {
			name string
			file utils.StreamEvidenceFile
		}{{"client", m.Client}, {"server", m.Server}} {
			name := direction.name + ".bin"
			data, err := os.ReadFile(filepath.Join(dir, name))
			digest := sha256.Sum256(data)
			if err != nil || direction.file.Name != name || direction.file.Length != int64(len(data)) || direction.file.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("invalid %s in %s: %v", name, dir, err)
			}
			offset := int64(0)
			for _, span := range m.Spans {
				if span.Direction != "client" && span.Direction != "server" {
					t.Fatalf("invalid span direction in %s: %+v", dir, span)
				}
				if span.Direction != direction.name {
					continue
				}
				if span.Offset != offset || span.Length < 0 || int64(span.Length) > int64(len(data))-offset || span.Datagram || span.DiscardedBytes != 0 {
					t.Fatalf("invalid %s span in %s: %+v (%d bytes)", direction.name, dir, span, len(data))
				}
				if span.Length > 0 {
					end := offset + int64(span.Length)
					got[packetKey{span.TimestampNs, sha256.Sum256(data[offset:end])}]++
					payloadSpans++
					offset = end
				}
			}
			if offset != int64(len(data)) {
				t.Fatalf("%s spans cover %d of %d bytes in %s", name, offset, len(data), dir)
			}
			payloadBytes += offset
		}
		if payloadSpans != 1 {
			t.Fatalf("expected one payload span in %s, got %d", dir, payloadSpans)
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("stream payload/timestamp multiset differs: %d distinct input keys, %d distinct output keys", len(want), len(got))
	}
	t.Logf("verified %d stream exports against input payloads and timestamps (%d payload bytes)", len(entries), payloadBytes)
}

func checkRecheckAuditMultiset[T any](t *testing.T, typ string, expected int, baseline, finite []T) {
	t.Helper()
	count := func(rows []T) map[[sha256.Size]byte]int {
		counts := make(map[[sha256.Size]byte]int, len(rows))
		for _, row := range rows {
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			counts[sha256.Sum256(data)]++
		}
		return counts
	}
	if len(baseline) != expected || len(finite) != expected || !reflect.DeepEqual(count(baseline), count(finite)) {
		t.Fatalf("%s audit multiset changed: baseline=%d finite=%d expected=%d", typ, len(baseline), len(finite), expected)
	}
}
