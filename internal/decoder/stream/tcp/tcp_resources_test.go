package tcp

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestCompletedConnectionsReleaseReadersAndPayloadDuringCapture(t *testing.T) {
	previous := decoderconfig.Instance
	configuration := *decoderconfig.DefaultConfig
	configuration.Quiet, configuration.SaveConns = true, false
	configuration.StreamDecoderBufSize = 1
	decoderconfig.Instance = &configuration
	t.Cleanup(func() { decoderconfig.Instance = previous })
	factory := newStreamFactory()
	flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0xfd, 0xe8})
	ctx := &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(100, 0)}}
	for iteration := range 32 {
		connection := factory.New(flow, transport, ctx).(*tcpConnection)
		connection.feedData(reassembly.TCPDirClientToServer, bytes.Repeat([]byte{0xff}, 16<<10), ctx)
		if iteration == 0 {
			var closers sync.WaitGroup
			for range 8 {
				closers.Go(func() { connection.client.CloseData(); connection.server.CloseData() })
			}
			closers.Wait()
		}
		connection.ReassemblyComplete(ctx, flow, "owned completion")
		if len(factory.readerSnapshot()) != 0 || factory.numActive != 0 {
			t.Fatal("completed connection retained reader tasks")
		}
		if len(factory.streamReaders) != 2 || len(factory.freeReaderSlots) != 2 {
			t.Fatalf("reader registry grows with historical connections: slots=%d free=%d", len(factory.streamReaders), len(factory.freeReaderSlots))
		}
		if len(connection.client.DataSlice()) != 0 || len(connection.server.DataSlice()) != 0 || len(connection.merged) != 0 || connection.decoder != nil {
			t.Fatal("completed connection retained payload/decoder references")
		}
		if connection.client.NumBytes() != 16<<10 {
			t.Fatal("lifetime byte counters were discarded with payload")
		}
		connection.releaseResources()
	}
	factory.wg.Wait()
}

func TestOpenConnectionsDoNotAllocateDrainTasks(t *testing.T) {
	previous := decoderconfig.Instance
	configuration := *decoderconfig.DefaultConfig
	configuration.StreamDecoderBufSize = 4096
	configuration.Quiet = true
	decoderconfig.Instance = &configuration
	t.Cleanup(func() { decoderconfig.Instance = previous })
	factory := newStreamFactory()
	flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0xfd, 0xe8})
	ctx := &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var connections []*tcpConnection
	for range 1000 {
		c := factory.New(flow, transport, ctx).(*tcpConnection)
		connections = append(connections, c)
		if c.client.DataChan() != nil || c.server.DataChan() != nil {
			t.Fatal("drain-only channels allocated")
		}
	}
	runtime.ReadMemStats(&after)
	for _, c := range connections {
		c.releaseResources()
	}
	factory.wg.Wait()
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 16<<20 {
		t.Fatalf("1000 idle streams allocated %d bytes", allocated)
	}
	t.Logf("1000 open streams allocated %d bytes", allocated)
}
