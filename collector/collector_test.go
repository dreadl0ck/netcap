package collector

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"testing"
	"time"
)

func TestCollectPCAP(t *testing.T) {

	// init collector
	c := New(Config{
		Live:                false,
		Workers:             12,
		PacketBufferSize:    100,
		WriteUnknownPackets: false,
		Promisc:             false,
		SnapLen:             1514,
		BaseLayer:           utils.GetBaseLayer("ethernet"),
		DecodeOptions:       utils.GetDecodeOptions("datagrams"),
		FileStorage:         "",
		Quiet:               true,
		EncoderConfig: encoder.Config{
			Buffer:          true,
			Compression:     true,
			CSV:             false,
			IncludeEncoders: "",
			ExcludeEncoders: "",
			Out:             "../tests/collector-test",
			Source:          "unit tests",
			Version:         netcap.Version,
			IncludePayloads: false,
			Export:          false,
			AddContext:      true,
			MemBufferSize:   1024*1024*10,
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:      false,
			LocalDNS:        false,
			MACDB:           true,
			Ja3DB:           true,
			ServiceDB:       true,
			GeolocationDB:   true,
		},
		DPI: false,
	})

	c.PrintConfiguration()

	// start timer
	start := time.Now()

	if err := c.CollectPcapNG("../tests/The-Ultimate-PCAP-v20200224.pcapng"); err != nil {
		t.Fatal("failed to collect audit records from pcapng file: ", err)
	}

	fmt.Println("done in", time.Since(start))
}
