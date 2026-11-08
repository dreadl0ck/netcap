package reassembly

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestInOrderAssemblyDoesNotAllocateOutOfOrderPages(t *testing.T) {
	factory := &dueFactory{streams: make(map[key][]*dueRecorder)}
	a := NewAssembler(NewStreamPool(factory))
	flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Unix(100, 0)})
	a.AssembleWithContext(flow, &layers.TCP{SrcPort: 1000, DstPort: 2000, SYN: true, Seq: 1}, &ctx)
	for sequence := uint32(2); sequence < 12; sequence++ {
		a.AssembleWithContext(flow, &layers.TCP{SrcPort: 1000, DstPort: 2000, Seq: sequence,
			BaseLayer: layers.BaseLayer{Payload: []byte("x")}}, &ctx)
	}
	if a.pc.size != 0 || len(a.pc.free) != 0 || a.pc.used != 0 {
		t.Fatalf("in-order traffic allocated page cache: size=%d used=%d", a.pc.size, a.pc.used)
	}
	a.AssembleWithContext(flow, &layers.TCP{SrcPort: 1000, DstPort: 2000, Seq: 100,
		BaseLayer: layers.BaseLayer{Payload: []byte("queued")}}, &ctx)
	if a.pc.size != initialAllocSize || a.pc.used != 1 {
		t.Fatalf("first out-of-order packet did not initialize cache: size=%d used=%d", a.pc.size, a.pc.used)
	}
	a.FlushAll()
	if a.pc.used != 0 {
		t.Fatal("flush retained allocated pages in use")
	}
}
