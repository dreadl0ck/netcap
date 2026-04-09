package collector_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// TestCommunityIDOnFingerprints verifies that all fingerprint audit records
// produced from https.pcap have a non-empty CommunityID.
func TestCommunityIDOnFingerprints(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "..")
	pcapPath := filepath.Join(projectRoot, "pcaps", "testfiles", "https.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("PCAP file not found: %s", pcapPath)
	}

	outputDir := t.TempDir()

	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             1,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &config.Config{
			Buffer:                  true,
			Compression:             false,
			CSV:                     false,
			Proto:                   true,
			IncludeDecoders:         "",
			ExcludeDecoders:         "",
			Out:                     outputDir,
			Source:                  "https.pcap community-id test",
			IncludePayloads:         false,
			ExportMetrics:           false,
			AddContext:              false, // intentionally off to verify CommunityID is computed regardless
			MemBufferSize:           defaults.BufferSize,
			FlushEvery:              defaults.FlushEvery,
			DefragIPv4:              false,
			Checksum:                false,
			NoOptCheck:              true,
			IgnoreFSMerr:            true,
			AllowMissingInit:        true,
			Debug:                   testing.Verbose(),
			Quiet:                   !testing.Verbose(),
			WriteIncomplete:         true,
			CompressionBlockSize:    defaults.CompressionBlockSize,
			CompressionLevel:        defaults.CompressionLevel,
			NumStreamWorkers:        runtime.NumCPU(),
			StreamBufferSize:        100,
			IgnoreDecoderInitErrors: true,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("default"),
		DPI:           false,
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         false,
			ServiceDB:     false,
			GeolocationDB: false,
		},
		OutDirPermission:      0o755,
		ReassembleConnections: true,
	})

	if c == nil {
		t.Fatal("collector is nil")
	}

	if err := c.CollectPcap(pcapPath); err != nil {
		t.Fatalf("failed to process pcap: %v", err)
	}

	// Verify TCP records have CommunityID (covers JA4T fingerprints)
	t.Run("TCP", func(t *testing.T) {
		records := readTCPRecords(t, outputDir)
		if len(records) == 0 {
			t.Fatal("no TCP records found")
		}

		var withJa4t int
		for _, rec := range records {
			if rec.Ja4T == "" {
				continue
			}
			withJa4t++
			if rec.CommunityID == "" {
				t.Errorf("TCP record with JA4T=%s has empty CommunityID (SrcIP=%s DstIP=%s SrcPort=%d DstPort=%d)",
					rec.Ja4T, rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort)
			}
		}

		if withJa4t == 0 {
			t.Fatal("no TCP records with JA4T fingerprints found")
		}
		t.Logf("checked %d TCP records with JA4T fingerprints (of %d total)", withJa4t, len(records))
	})

	// Verify TLSClientHello records have CommunityID (covers JA4 fingerprints)
	t.Run("TLSClientHello", func(t *testing.T) {
		records := readTLSClientHelloRecords(t, outputDir)
		if len(records) == 0 {
			t.Fatal("no TLSClientHello records found")
		}

		for _, rec := range records {
			if rec.CommunityID == "" {
				t.Errorf("TLSClientHello with JA4=%s has empty CommunityID (SrcIP=%s DstIP=%s)",
					rec.Ja4, rec.SrcIP, rec.DstIP)
			}
		}
		t.Logf("checked %d TLSClientHello records", len(records))
	})

	// Verify TLSServerHello records have CommunityID (covers JA4S fingerprints)
	t.Run("TLSServerHello", func(t *testing.T) {
		records := readTLSServerHelloRecords(t, outputDir)
		if len(records) == 0 {
			t.Fatal("no TLSServerHello records found")
		}

		for _, rec := range records {
			if rec.CommunityID == "" {
				t.Errorf("TLSServerHello with JA4S=%s has empty CommunityID (SrcIP=%s DstIP=%s)",
					rec.Ja4S, rec.SrcIP, rec.DstIP)
			}
		}
		t.Logf("checked %d TLSServerHello records", len(records))
	})
}

func findAuditRecordFile(t *testing.T, dir, baseName string) string {
	t.Helper()

	// try uncompressed first, then gzipped
	for _, name := range []string{baseName + ".ncap", baseName + ".ncap.gz"} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Size() > 0 {
			return p
		}
	}

	// list what was actually created for debugging
	files, _ := os.ReadDir(dir)
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	t.Fatalf("no %s audit record file found in %s; files present: %v", baseName, dir, names)
	return ""
}

func readTCPRecords(t *testing.T, dir string) []*types.TCP {
	t.Helper()

	path := findAuditRecordFile(t, dir, "TCP")
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer r.Close()

	header, err := r.ReadHeader()
	if err != nil {
		t.Fatalf("failed to read header: %v", err)
	}
	if header.Type != types.Type_NC_TCP {
		t.Fatalf("unexpected record type: %s", header.Type)
	}

	var records []*types.TCP
	for {
		rec := new(types.TCP)
		err = r.Next(rec)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			t.Fatalf("failed to read record: %v", err)
		}
		records = append(records, rec)
	}
	return records
}

func readTLSClientHelloRecords(t *testing.T, dir string) []*types.TLSClientHello {
	t.Helper()

	path := findAuditRecordFile(t, dir, "TLSClientHello")
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer r.Close()

	header, err := r.ReadHeader()
	if err != nil {
		t.Fatalf("failed to read header: %v", err)
	}
	if header.Type != types.Type_NC_TLSClientHello {
		t.Fatalf("unexpected record type: %s", header.Type)
	}

	var records []*types.TLSClientHello
	for {
		rec := new(types.TLSClientHello)
		err = r.Next(rec)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			t.Fatalf("failed to read record: %v", err)
		}
		records = append(records, rec)
	}
	return records
}

func readTLSServerHelloRecords(t *testing.T, dir string) []*types.TLSServerHello {
	t.Helper()

	path := findAuditRecordFile(t, dir, "TLSServerHello")
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer r.Close()

	header, err := r.ReadHeader()
	if err != nil {
		t.Fatalf("failed to read header: %v", err)
	}
	if header.Type != types.Type_NC_TLSServerHello {
		t.Fatalf("unexpected record type: %s", header.Type)
	}

	var records []*types.TLSServerHello
	for {
		rec := new(types.TLSServerHello)
		err = r.Next(rec)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			t.Fatalf("failed to read record: %v", err)
		}
		records = append(records, rec)
	}
	return records
}

func init() {
	// Suppress fmt output from collector during tests
	fmt.Fprint(io.Discard, "")
}
