package collector_test

import (
	"context"
	"fmt"
	"github.com/dreadl0ck/netcap/collector"
	"log"
	"os/exec"
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
		fmt.Println("live capture done in", time.Since(start))
	}()

	// generate some traffic by pinging localhost
	go func() {
		fmt.Println("pinging localhost")
		out, err := exec.Command("ping", "localhost").CombinedOutput()
		if err != nil {
			fmt.Println(string(out))
			log.Fatal(err)
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
	// init collector
	c := collector.New(collector.Config{
		WriteUnknownPackets: false,
		Workers:             12,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &config.Config{
			Buffer:               true,
			Compression:          true,
			CSV:                  false,
			Proto: true,
			IncludeDecoders:      "",
			ExcludeDecoders:      "",
			Out:                  "../tests/collector-test",
			Source:               "unit tests",
			IncludePayloads:      false,
			ExportMetrics:        false,
			AddContext:           true,
			MemBufferSize:        defaults.BufferSize,
			FlushEvery:           defaults.FlushEvery,
			DefragIPv4:           defaults.DefragIPv4,
			Checksum:             defaults.Checksum,
			NoOptCheck:           defaults.NoOptCheck,
			IgnoreFSMerr:         defaults.IgnoreFSMErr,
			AllowMissingInit:     defaults.AllowMissingInit,
			Debug:                false,
			HexDump:              false,
			WaitForConnections:   true,
			WriteIncomplete:      false,
			MemProfile:           "",
			ConnFlushInterval:    10000,
			ConnTimeOut:          10,
			FlowFlushInterval:    2000,
			FlowTimeOut:          10,
			CloseInactiveTimeOut: 24 * time.Hour,
			ClosePendingTimeOut:  5 * time.Second,
			FileStorage:          "",
			Quiet:                true,
			CompressionBlockSize: defaults.CompressionBlockSize,
			CompressionLevel: defaults.CompressionLevel,
			NumStreamWorkers: runtime.NumCPU(),
			StreamBufferSize: 100,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("datagrams"),
		DPI:           false,
		ResolverConfig: resolvers.Config{
			ReverseDNS:    false,
			LocalDNS:      false,
			MACDB:         true,
			Ja3DB:         true,
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
