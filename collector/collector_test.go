package collector_test

import (
	"context"
	"github.com/dreadl0ck/netcap/collector"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// TestCaptureLive will test capturing traffic live from the loopback interface
func TestCaptureLive(t *testing.T) {
	// collector.DefaultConfig embeds resolvers.DefaultConfig, which sets
	// GeolocationDB: true, so this test needs the GeoLite2 files just as
	// TestCapturePCAP does. See requireGeolocationDBs.
	requireGeolocationDBs(t)

	// prepare default config
	collector.DefaultConfig.DecoderConfig.Out = "../tests/collector-test-live"
	collector.DefaultConfig.DecoderConfig.Source = "unit tests live capture"
	collector.DefaultConfig.DecoderConfig.Quiet = true

	// init config
	c := collector.New(collector.DefaultConfig)
	c.PrintConfiguration()

	// start timer
	start := time.Now()

	// init context
	ctx, cancel := context.WithCancel(context.Background())

	// stop collector after five seconds
	go func() {
		time.Sleep(5 * time.Second)
		cancel()
		t.Log("live capture done in", time.Since(start))
	}()

	// generate some traffic by pinging localhost (limited to 5 pings)
	go func() {
		t.Log("pinging localhost")
		out, err := exec.Command("ping", "-c", "5", "localhost").CombinedOutput()
		if err != nil {
			t.Log(string(out))
			t.Log("ping error:", err)
		}
	}()

	// set localhost interface
	interfaceName := "lo"
	if runtime.GOOS == "darwin" {
		interfaceName = "lo0"
	}

	// collect packets from interface
	err := c.CollectLive(interfaceName, "", ctx)
	if err != nil {
		t.Fatal("failed to collect live packets: ", err)
	}
}

func TestCapturePCAP(t *testing.T) {
	// This is the only collector test that enables GeolocationDB, and
	// initGeolocationDB deliberately calls log.Fatal when the GeoLite2 files are
	// absent -- correct for the CLI, where the user asked for geolocation, but
	// it takes the whole test binary down with it. The databases are a separate
	// download (MaxMind requires a licence), so they are missing on any clean
	// checkout and in CI, where this failed the entire collector package with no
	// "--- FAIL" line to explain it.
	requireGeolocationDBs(t)

	// init collector
	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             12,
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
			Out:                     "../tests/collector-test",
			Source:                  "unit tests",
			IncludePayloads:         false,
			ExportMetrics:           false,
			AddContext:              true,
			MemBufferSize:           defaults.BufferSize,
			FlushEvery:              defaults.FlushEvery,
			DefragIPv4:              defaults.DefragIPv4,
			Checksum:                defaults.Checksum,
			NoOptCheck:              defaults.NoOptCheck,
			IgnoreFSMerr:            defaults.IgnoreFSMErr,
			AllowMissingInit:        defaults.AllowMissingInit,
			Debug:                   false,
			HexDump:                 false,
			WaitForConnections:      true,
			WriteIncomplete:         false,
			MemProfile:              "",
			ConnFlushInterval:       10000,
			ConnTimeOut:             10,
			FlowFlushInterval:       2000,
			FlowTimeOut:             10,
			CloseInactiveTimeOut:    30 * time.Second,
			ClosePendingTimeOut:     5 * time.Second,
			FileStorage:             "",
			Quiet:                   true,
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
			ReverseDNS: false,
			LocalDNS:   false,
			MACDB:      true,

			ServiceDB:     true,
			GeolocationDB: true,
		},
		OutDirPermission:      0o700,
		FreeOSMem:             0,
		ReassembleConnections: true,
	})

	c.PrintConfiguration()

	if err := c.CollectPcapNG("../tests/The-Ultimate-PCAP-v20200224.pcapng"); err != nil {
		t.Fatal("failed to collect audit records from pcapng file: ", err)
	}
}

// requireGeolocationDBs skips the calling test unless the GeoLite2 databases
// are present.
//
// It checks for the files rather than trusting a build tag or an env var so it
// is correct wherever it runs: a contributor who has never downloaded them, a
// CI container that cannot (MaxMind requires a licence key), and a full local
// checkout that has them all get the right behaviour with no configuration.
func requireGeolocationDBs(t *testing.T) {
	t.Helper()

	for _, name := range []string{"GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"} {
		path := filepath.Join(resolvers.DataBaseFolderPath, name)
		if _, err := os.Stat(path); err != nil {
			t.Skipf("geolocation database %s not available (%v); "+
				"download the GeoLite2 databases to run this test", path, err)
		}
	}
}
