package collector

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// TestCaptureLive will test capturing traffic live from the loopback interface
func TestCaptureLive(t *testing.T) {

	// prepare default config
	DefaultConfig.DecoderConfig.Out = "../tests/collector-test-live"
	DefaultConfig.DecoderConfig.Source = "unit tests live capture"

	c := New(DefaultConfig)
	c.PrintConfiguration()

	// start timer
	start := time.Now()

	go func() {
		time.Sleep(5 * time.Second)
		c.Stop()
		fmt.Println("live capture done in", time.Since(start))
		os.Exit(0)
	}()

	interfaceName := "lo"
	if runtime.GOOS == "darwin" {
		interfaceName = "lo0"
	}

	err := c.CollectLive(interfaceName, "")
	if err != nil {
		t.Fatal("failed to collect live packets: ", err)
	}
}

func TestCapturePCAP(t *testing.T) {
	// init collector
	c := New(Config{
		WriteUnknownPackets: false,
		Workers:             12,
		PacketBufferSize:    100,
		SnapLen:             defaults.SnapLen,
		Promisc:             false,
		DecoderConfig: &decoder.Config{
			Buffer:               true,
			Compression:          true,
			CSV:                  false,
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
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("datagrams"),
		Quiet:         true,
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
