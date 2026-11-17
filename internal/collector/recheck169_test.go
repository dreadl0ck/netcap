package collector

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
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
