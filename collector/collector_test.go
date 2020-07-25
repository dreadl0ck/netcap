package collector

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestCaptureLive will test capturing traffic live from the loopback interface
func TestCaptureLive(t *testing.T) {

	// init collector
	// TODO: use base config from PCAP test, and set to live mode
	c := New(Config{
		WriteUnknownPackets: false,
		Workers:             12,
		PacketBufferSize:    100,
		SnapLen:             1514,
		Promisc:             false,
		DecoderConfig: decoder.Config{
			Buffer:               true,
			Compression:          true,
			CSV:                  false,
			IncludeDecoders:      "",
			ExcludeDecoders:      "",
			Out:                  "../tests/collector-test-live",
			Source:               "unit tests live capture",
			IncludePayloads:      false,
			Export:               false,
			AddContext:           true,
			MemBufferSize:        netcap.DefaultBufferSize,
			FlushEvery:           netcap.DefaultFlushEvery,
			DefragIPv4:           netcap.DefaultDefragIPv4,
			Checksum:             netcap.DefaultChecksum,
			NoOptCheck:           netcap.DefaultNoOptCheck,
			IgnoreFSMerr:         netcap.DefaultIgnoreFSMErr,
			AllowMissingInit:     netcap.DefaultAllowMissingInit,
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
		OutDirPermission:      0700,
		FreeOSMem:             0,
		ReassembleConnections: true,
	})

	c.PrintConfiguration()

	// start timer
	start := time.Now()

	go func() {
		time.Sleep(5 * time.Second)
		c.Stop()
		fmt.Println("live capture done in", time.Since(start))
		os.Exit(0)
	}()

	var iface = "lo"
	if runtime.GOOS == "darwin" {
		iface = "lo0"
	}

	err := c.CollectLive(iface, "")
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
		SnapLen:             1514,
		Promisc:             false,
		DecoderConfig: decoder.Config{
			Buffer:               true,
			Compression:          true,
			CSV:                  false,
			IncludeDecoders:      "",
			ExcludeDecoders:      "",
			Out:                  "../tests/collector-test",
			Source:               "unit tests",
			IncludePayloads:      false,
			Export:               false,
			AddContext:           true,
			MemBufferSize:        netcap.DefaultBufferSize,
			FlushEvery:           netcap.DefaultFlushEvery,
			DefragIPv4:           netcap.DefaultDefragIPv4,
			Checksum:             netcap.DefaultChecksum,
			NoOptCheck:           netcap.DefaultNoOptCheck,
			IgnoreFSMerr:         netcap.DefaultIgnoreFSMErr,
			AllowMissingInit:     netcap.DefaultAllowMissingInit,
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
		OutDirPermission:      0700,
		FreeOSMem:             0,
		ReassembleConnections: true,
	})

	c.PrintConfiguration()

	if err := c.CollectPcapNG("../tests/The-Ultimate-PCAP-v20200224.pcapng"); err != nil {
		t.Fatal("failed to collect audit records from pcapng file: ", err)
	}
}
