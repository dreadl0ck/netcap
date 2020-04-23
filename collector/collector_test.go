package collector

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"os"
	"testing"
	"time"
)

// TestCaptureLive will test capturing traffic live from the loopback interface
func TestCaptureLive(t *testing.T) {

	// init collector
	c := New(Config{
		WriteUnknownPackets: false,
		Workers:             12,
		PacketBufferSize:    100,
		SnapLen:             1514,
		Promisc:             false,
		EncoderConfig: encoder.Config{
			Buffer:               true,
			Compression:          true,
			CSV:                  false,
			IncludeEncoders:      "",
			ExcludeEncoders:      "",
			Out:                  "../tests/collector-test-live",
			Source:               "unit tests live capture",
			IncludePayloads:      false,
			Export:               false,
			AddContext:           true,
			MemBufferSize:        netcap.DefaultBufferSize,
			FlushEvery:           100,
			NoDefrag:             false,
			Checksum:             false,
			NoOptCheck:           false,
			IgnoreFSMerr:         false,
			AllowMissingInit:     false,
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
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("datagrams"),
		FileStorage:   "",
		Quiet:         false,
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

	err := c.CollectLive("lo0", "")
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
		EncoderConfig: encoder.Config{
			Buffer:               true,
			Compression:          true,
			CSV:                  false,
			IncludeEncoders:      "",
			ExcludeEncoders:      "",
			Out:                  "../tests/collector-test",
			Source:               "unit tests",
			IncludePayloads:      false,
			Export:               false,
			AddContext:           true,
			MemBufferSize:        netcap.DefaultBufferSize,
			FlushEvery:           100,
			NoDefrag:             false,
			Checksum:             false,
			NoOptCheck:           false,
			IgnoreFSMerr:         false,
			AllowMissingInit:     false,
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
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("datagrams"),
		FileStorage:   "",
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

	if err := c.CollectPcapNG("../tests/The-Ultimate-PCAP-v20200224.pcapng"); err != nil {
		t.Fatal("failed to collect audit records from pcapng file: ", err)
	}

	fmt.Println("done in", time.Since(start))
}
