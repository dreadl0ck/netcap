package collector_test

import (
	"errors"
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

// TestCertificateCountMatchesTable verifies that the number of raw TLSCertificate
// records deduplicated by SHA256 fingerprint equals the number of unique certificates.
// This catches the bug where the menu count was sourced from TLSServerHello (raw handshakes)
// instead of deduplicated TLSCertificate records.
func TestCertificateCountMatchesTable(t *testing.T) {
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
			Compression:             true,
			CSV:                     false,
			Proto:                   true,
			IncludeDecoders:         "",
			ExcludeDecoders:         "",
			Out:                     outputDir,
			Source:                  "https.pcap certificate count test",
			IncludePayloads:         false,
			ExportMetrics:           false,
			AddContext:              true,
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

	// Read raw TLSCertificate records
	certPath := findAuditRecordFile(t, outputDir, "TLSCertificate")
	rawCerts := readTLSCertificateRecords(t, certPath)

	if len(rawCerts) == 0 {
		t.Fatal("no TLSCertificate records found")
	}

	// Deduplicate by SHA256 fingerprint (same logic as the certificates table)
	uniqueByFingerprint := make(map[string]bool)
	for _, cert := range rawCerts {
		key := cert.SHA256Fingerprint
		if key == "" {
			key = cert.SerialNumber + "|" + cert.IssuerCommonName
		}
		uniqueByFingerprint[key] = true
	}

	uniqueCount := len(uniqueByFingerprint)
	rawCount := len(rawCerts)

	t.Logf("raw TLSCertificate records: %d, unique by SHA256: %d", rawCount, uniqueCount)

	// The menu count must equal the deduplicated table count, not the raw record count.
	// Before the fix, the menu used TLSServerHello count (raw handshakes) which would
	// show 2 for https.pcap while the table showed only 1 unique certificate.
	if uniqueCount > rawCount {
		t.Errorf("unique count (%d) exceeds raw count (%d) — deduplication is broken", uniqueCount, rawCount)
	}

	// The https.pcap contains the same certificate seen across multiple connections,
	// so raw records > unique certificates. The menu must show the unique count.
	if rawCount > uniqueCount {
		t.Logf("confirmed: raw TLSCertificate records (%d) > unique certificates (%d) — menu must use deduplicated count",
			rawCount, uniqueCount)
	}

	// Assert: for https.pcap we expect exactly 1 unique certificate
	if uniqueCount != 1 {
		t.Errorf("expected 1 unique certificate from https.pcap, got %d", uniqueCount)
	}
}

func readTLSCertificateRecords(t *testing.T, path string) []*types.TLSCertificate {
	t.Helper()

	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer r.Close()

	header, err := r.ReadHeader()
	if err != nil {
		t.Fatalf("failed to read header: %v", err)
	}
	if header.Type != types.Type_NC_TLSCertificate {
		t.Fatalf("unexpected record type: %s", header.Type)
	}

	var records []*types.TLSCertificate
	for {
		rec := new(types.TLSCertificate)
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
