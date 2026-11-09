package reassembly

import (
	"fmt"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type streamLimitRecorder struct {
	retainingPageStream
	completions int
	delivered   int
}

func (s *streamLimitRecorder) New(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
	return s
}

func (s *streamLimitRecorder) ReassembledSG(sg ScatterGather, ac AssemblerContext) {
	n, _ := sg.Lengths()
	s.delivered += n
	s.retainingPageStream.ReassembledSG(sg, ac)
}

func (s *streamLimitRecorder) ReassemblyComplete(AssemblerContext, gopacket.Flow, string) bool {
	s.completions++
	return true
}

func TestStreamLimitClosesAndReleasesRetainedPages(t *testing.T) {
	for _, budget := range []int64{0, 8 * PageAllocationBytes} {
		for _, queued := range []bool{false, true} {
			for _, flushPage := range []bool{false, true} {
				t.Run(fmt.Sprintf("budget=%d/queued=%t/flush=%t", budget, queued, flushPage), func(t *testing.T) {
					b, err := NewPageBudget(budget, nil)
					if err != nil {
						t.Fatal(err)
					}
					for range 32 {
						s := new(streamLimitRecorder)
						a := NewAssembler(NewStreamPool(s))
						a.SetPageBudget(b)
						a.MaxStreamBytes = 6
						if flushPage {
							a.MaxBufferedPagesPerConnection = 1
						}
						network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
						ctx := &assemblerSimpleContext{Timestamp: time.Unix(1, 0)}
						a.AssembleWithContext(network, &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true, Seq: 100}, ctx)
						seq := uint32(101)
						for _, payload := range []string{"abc", "def", "ignored"} {
							if queued {
								seq += 10
								ctx.Timestamp = ctx.Timestamp.Add(time.Second)
							}
							packet := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: seq, ACK: true}
							packet.Payload = []byte(payload)
							a.AssembleWithContext(network, packet, ctx)
							seq += uint32(len(payload))
						}
						if a.pc.used != 0 {
							t.Fatalf("stream byte limit retained pages: used=%d", a.pc.used)
						}
						if b != nil && b.Health().RetainedBytes != 0 {
							t.Fatalf("stream byte limit retained budget: %+v", b.Health())
						}
						if !queued && s.delivered != 9 {
							t.Fatalf("limit boundary changed delivery: got %d bytes, want 9 including retained prefix", s.delivered)
						}
						a.FlushAll()
						a.FlushAll()
						if s.completions != 1 || b.Error() != nil {
							t.Fatalf("completion=%d budget error=%v", s.completions, b.Error())
						}
						a.Release()
					}
				})
			}
		}
	}
}
