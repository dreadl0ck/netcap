package collector

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type expiringStream struct{ closed chan struct{} }

func (s *expiringStream) New(gopacket.Flow, gopacket.Flow, reassembly.AssemblerContext) reassembly.Stream {
	return s
}
func (*expiringStream) Accept(*layers.TCP, reassembly.TCPFlowDirection, reassembly.Sequence) bool {
	return true
}
func (*expiringStream) ReassembledSG(reassembly.ScatterGather, reassembly.AssemblerContext) {}
func (s *expiringStream) ReassemblyComplete(reassembly.AssemblerContext, gopacket.Flow, string) bool {
	close(s.closed)
	return true
}

func TestLiveMaintenanceExpiresWithoutAnotherPacketOrOutputFlush(t *testing.T) {
	c := New(Config{Workers: 1, PacketBufferSize: 4, ReassembleConnections: true,
		LiveMaintenanceInterval: time.Millisecond, LiveFlushInterval: 0,
		DecoderConfig: &config.Config{ClosePendingTimeOut: time.Minute, CloseInactiveTimeOut: time.Minute}})
	stream := &expiringStream{closed: make(chan struct{})}
	a := reassembly.NewAssembler(reassembly.NewStreamPoolWithIdleExpiry(stream))
	a.AssembleWithContext(gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1}),
		&layers.TCP{SrcPort: 1000, DstPort: 2000, SYN: true, Seq: 1}, lifecycleContext{time.Now().Add(-time.Hour)})
	c.workers = append(c.workers, c.worker(a))
	c.numWorkers, c.acceptingPackets = 1, true
	stop := c.startLiveMaintenance()
	defer func() { close(stop); c.Stop() }()
	select {
	case <-stream.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("idle stream did not expire without a subsequent packet")
	}
}

func TestLiveMaintenanceSharesAdmissionFIFO(t *testing.T) {
	c := rawPacketCollector(3, 10, gopacket.Default)
	before, after := lifecyclePayload(), lifecyclePayload()
	c.handlePacket(before)
	ref := time.Unix(100, 0)
	c.maintainStreams(ref)
	c.handlePacket(after)
	for _, worker := range c.workers {
		seenControl := false
		for len(worker) > 0 {
			packet := <-worker
			if control, ok := packet.(*workerControl); ok {
				if seenControl || !control.ref.Equal(ref) {
					t.Fatal("invalid maintenance control")
				}
				seenControl = true
				continue
			}
			if (packet == after) != seenControl {
				t.Fatal("maintenance overtook admitted data")
			}
			c.wg.Done()
		}
		if !seenControl {
			t.Fatal("idle worker missed maintenance")
		}
	}
	c.acceptingPackets = false
	c.maintainStreams(ref)
	for _, worker := range c.workers {
		if len(worker) != 0 {
			t.Fatal("maintenance queued after admission closed")
		}
	}
}
