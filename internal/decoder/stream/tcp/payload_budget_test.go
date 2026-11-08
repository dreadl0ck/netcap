package tcp

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestSharedPayloadBudgetNeverExceedsLimitDuringConcurrentReservations(t *testing.T) {
	var canceled, accepted atomic.Int32
	budget := &retainedPayloadBudget{limit: 7, onExceeded: func() { canceled.Add(1) }}
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			if budget.reserve(1) {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 7 || budget.used.Load() != 7 || budget.peak.Load() != 7 || budget.rejected.Load() != 57 || canceled.Load() != 1 {
		t.Fatalf("accepted=%d retained=%d peak=%d rejected=%d canceled=%d", accepted.Load(), budget.used.Load(), budget.peak.Load(), budget.rejected.Load(), canceled.Load())
	}
	budget.release(7)
	if budget.reserve(1) || budget.used.Load() != 0 {
		t.Fatal("aborted capture resumed retaining payload")
	}
}

func payloadBudgetFactory(t *testing.T, limit int64, canceled *atomic.Int32) (*connectionFactory, func(byte) *tcpConnection, *context) {
	t.Helper()
	previous := decoderconfig.Instance
	configuration := *decoderconfig.DefaultConfig
	configuration.Quiet, configuration.SaveConns, configuration.StreamDecoderBufSize = true, false, 1
	decoderconfig.Instance = &configuration
	t.Cleanup(func() { decoderconfig.Instance = previous })
	factory := newStreamFactory()
	t.Cleanup(func() {
		pending := factory.readerSnapshot()
		for _, reader := range pending {
			reader.CloseData()
		}
		factory.wg.Wait()
		for _, reader := range pending {
			reader.(*tcpStreamReader).parent.releaseResources()
		}
	})
	if err := factory.configurePayloadBudget(limit, func() { canceled.Add(1) }); err != nil {
		t.Fatal(err)
	}
	ctx := &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(100, 0)}}
	newConnection := func(host byte) *tcpConnection {
		return factory.New(gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, host}, []byte{198, 51, 100, 1}),
			gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0xfd, 0xe8}), ctx).(*tcpConnection)
	}
	return factory, newConnection, ctx
}

func TestCompletedConnectionsReturnSharedPayloadBudget(t *testing.T) {
	var canceled atomic.Int32
	factory, newConnection, ctx := payloadBudgetFactory(t, 32, &canceled)
	for range 32 {
		connection := newConnection(1)
		connection.feedData(reassembly.TCPDirClientToServer, bytes.Repeat([]byte{0xff}, 16), ctx)
		connection.ReassemblyComplete(ctx, connection.net, "owned completion")
		if factory.payloadBudget.used.Load() != 0 {
			t.Fatal("completed reader retained budget")
		}
	}
	if canceled.Load() != 0 || factory.payloadBudget.peak.Load() != 16 {
		t.Fatal("lifetime input bytes were mistaken for retained memory")
	}
}

func TestPayloadBudgetIsSharedAcrossConnectionsAndCannotBeReplacedWhileActive(t *testing.T) {
	var canceled atomic.Int32
	factory, newConnection, ctx := payloadBudgetFactory(t, 24, &canceled)
	first, second := newConnection(1), newConnection(2)
	if err := factory.configurePayloadBudget(48, nil); err == nil {
		t.Fatal("active budget was replaced")
	}
	first.feedData(reassembly.TCPDirClientToServer, bytes.Repeat([]byte{0xff}, 16), ctx)
	second.feedData(reassembly.TCPDirClientToServer, bytes.Repeat([]byte{0xff}, 16), ctx)
	if first.client.NumBytes() != 16 || second.client.NumBytes() != 0 || canceled.Load() != 1 || factory.payloadBudget.used.Load() != 16 {
		t.Fatal("per-connection accounting multiplied the shared budget")
	}
	first.ReassemblyComplete(ctx, first.net, "owned completion")
	second.ReassemblyComplete(ctx, second.net, "owned completion")
	if factory.payloadBudget.used.Load() != 0 {
		t.Fatal("failed capture leaked retained budget")
	}
}
