package collector

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
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
	for _, name := range []string{"dns_query_fp.pcap", "dns_response_fp.pcap", "nbns_query_fp.pcap", "nbns_refresh_fp.pcap", "v169_midstream_psh_15k.pcap"} {
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
