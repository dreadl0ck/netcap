package reassembly

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type workerPoolBenchStream struct {
	bytes       uint64
	completions int
}

func (*workerPoolBenchStream) Accept(*layers.TCP, TCPFlowDirection, Sequence) bool {
	return true
}

func (s *workerPoolBenchStream) ReassembledSG(sg ScatterGather, _ AssemblerContext) {
	n, _ := sg.Lengths()
	s.bytes += uint64(n)
}

func (s *workerPoolBenchStream) ReassemblyComplete(AssemblerContext, gopacket.Flow, string) bool {
	s.completions++
	return true
}

type workerPoolBenchFactory struct{}

func (workerPoolBenchFactory) New(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
	return &workerPoolBenchStream{}
}

// BenchmarkWorkerPools isolates established-stream reassembly and pool contention.
// It excludes decoding, collector dispatch, real factory/stream callbacks, and
// production lifecycle work (creation, expiry, shutdown). MB/s counts TCP payload,
// not wire bytes. One operation sends two packets in each direction of one flow.
func BenchmarkWorkerPools(b *testing.B) {
	for _, reordered := range []bool{false, true} {
		workload := "in_order"
		if reordered {
			workload = "reordered"
		}
		for _, workers := range []int{1, 2, 4, 8} {
			for _, shared := range []bool{true, false} {
				mode := "worker_owned"
				if shared {
					mode = "shared_locked"
				}
				b.Run(fmt.Sprintf("%s/workers=%d/%s", workload, workers, mode), func(b *testing.B) {
					benchmarkWorkerPools(b, workers, shared, reordered)
				})
			}
		}
	}
}

func benchmarkWorkerPools(b *testing.B, workers int, shared, reordered bool) {
	b.StopTimer()
	const connections, payloadBytes, packetsPerOp = 256, 512, 4
	const bytesPerOp = payloadBytes * packetsPerOp
	type flowState struct {
		net    [2]gopacket.Flow
		tcp    [2]layers.TCP
		stream *workerPoolBenchStream
	}
	flows := make([]flowState, connections)
	assemblers := make([]*Assembler, workers)
	pools := make([]*StreamPool, 0, workers)
	factory := workerPoolBenchFactory{}
	ctx := &assemblerSimpleContext{Timestamp: time.Unix(1700000000, 0)}
	payload := make([]byte, payloadBytes)
	var assemblyMu sync.Mutex
	for w := range workers {
		if w == 0 || !shared {
			pools = append(pools, NewStreamPool(factory))
		}
		assemblers[w] = NewAssembler(pools[len(pools)-1])
		// Keep long benchmark runs from measuring drops after the byte limit.
		assemblers[w].MaxStreamBytes = 0
	}
	for i := range flows {
		f := &flows[i]
		a := assemblers[i%workers]
		f.net[0] = gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, byte(i)}, []byte{192, 0, 2, 1})
		f.net[1] = f.net[0].Reverse()
		f.tcp[0] = layers.TCP{SrcPort: 12345, DstPort: 80, Seq: 1000, SYN: true}
		f.tcp[1] = layers.TCP{SrcPort: 80, DstPort: 12345, Seq: 2000, SYN: true}
		for dir := range f.tcp {
			tcp := &f.tcp[dir]
			a.AssembleWithContext(f.net[dir], tcp, ctx)
			tcp.SYN = false
			tcp.Seq++
			tcp.Payload = payload
			seq := tcp.Seq
			if reordered {
				tcp.Seq += payloadBytes
			}
			a.AssembleWithContext(f.net[dir], tcp, ctx)
			if reordered && a.pc.used != 1 {
				b.Fatalf("warm flow %d direction %d: buffered pages = %d, want 1", i, dir, a.pc.used)
			}
			tcp.Seq = seq + payloadBytes
			if reordered {
				tcp.Seq = seq
			}
			a.AssembleWithContext(f.net[dir], tcp, ctx)
			tcp.Seq = seq + 2*payloadBytes
			if a.pc.used != 0 {
				b.Fatalf("warm flow %d direction %d: pages remain after gap fill", i, dir)
			}
		}
		k := key{f.net[0], f.tcp[0].TransportFlow()}
		f.stream = a.connPool.conns[k].c2s.stream.(*workerPoolBenchStream)
		if f.stream.bytes != bytesPerOp || f.stream.completions != 0 {
			b.Fatalf("warm flow %d: bytes=%d completions=%d", i, f.stream.bytes, f.stream.completions)
		}
	}
	for _, pool := range pools {
		want := connections / workers
		if shared {
			want = connections
		}
		if len(pool.conns) != want {
			b.Fatalf("warm pool cardinality = %d, want %d", len(pool.conns), want)
		}
	}

	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(workers)
	done.Add(workers)
	for w := range workers {
		go func() {
			defer done.Done()
			a := assemblers[w]
			assemble := func(flow gopacket.Flow, tcp *layers.TCP) {
				if shared {
					assemblyMu.Lock()
				}
				a.AssembleWithContext(flow, tcp, ctx)
				if shared {
					assemblyMu.Unlock()
				}
			}
			ready.Done()
			<-start
			// Global operation j belongs to worker j%workers and flow j%256.
			// No shared operation counter; every flow stays on its owning worker.
			for j := w; j < b.N; j += workers {
				f := &flows[j%connections]
				for dir := range f.tcp {
					tcp := &f.tcp[dir]
					seq := tcp.Seq
					if reordered {
						tcp.Seq += payloadBytes
					}
					assemble(f.net[dir], tcp)
					tcp.Seq = seq + payloadBytes
					if reordered {
						tcp.Seq = seq
					}
					assemble(f.net[dir], tcp)
					tcp.Seq = seq + 2*payloadBytes
				}
			}
		}()
	}
	ready.Wait()
	b.SetBytes(bytesPerOp)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	close(start)
	done.Wait()
	b.StopTimer()
	b.ReportMetric(float64(b.N)*packetsPerOp/b.Elapsed().Seconds(), "packets/s")

	for _, a := range assemblers {
		if a.pc.used != 0 {
			b.Fatalf("pages remain before flush: %s", a.Dump())
		}
	}
	closed := 0
	for _, a := range assemblers {
		closed += a.FlushAll()
	}
	if closed != connections {
		b.Fatalf("closed %d connections, want %d", closed, connections)
	}
	for i, f := range flows {
		ops := b.N / connections
		if i < b.N%connections {
			ops++
		}
		want := (uint64(ops) + 1) * bytesPerOp // Includes one warm operation.
		if f.stream.bytes != want || f.stream.completions != 1 {
			b.Errorf("flow %d: bytes=%d (want %d), completions=%d (want 1)", i, f.stream.bytes, want, f.stream.completions)
		}
	}
	for _, pool := range pools {
		if len(pool.conns) != 0 {
			b.Errorf("pool retains %d connections", len(pool.conns))
		}
	}
	for _, a := range assemblers {
		if a.pc.used != 0 || len(a.pc.free) != a.pc.size {
			b.Errorf("pages not returned after flush: %s", a.Dump())
		}
	}
}
