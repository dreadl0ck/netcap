package reassembly

import (
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

// Use public assembly/maintenance paths so the same benchmarks can be overlaid
// on the scan implementation, including packet-side index maintenance costs.
func benchmarkMaintenancePool(b *testing.B, size int) (*Assembler, []key, []layers.TCP, *assemblerSimpleContext) {
	b.Helper()
	a := NewAssembler(NewStreamPool(&testFactoryBench{}))
	keys := make([]key, size)
	packets := make([]layers.TCP, size)
	ctx := &assemblerSimpleContext{Timestamp: time.Unix(1700000000, 0), CaptureLength: 64, Length: 64}
	for i := range keys {
		keys[i] = snapshotKey(i)
		packets[i] = layers.TCP{
			SrcPort: 12345, DstPort: 80, SYN: true, Seq: 1000,
			BaseLayer: layers.BaseLayer{Payload: []byte("0123456789abcdef")},
		}
		packets[i].SetInternalPortsForTesting()
		a.AssembleWithContext(keys[i][0], &packets[i], ctx)
		packets[i].SYN = false
		packets[i].Seq += 1 + uint32(len(packets[i].Payload))
	}
	if len(a.connPool.conns) != size {
		b.Fatalf("pool cardinality = %d, want %d", len(a.connPool.conns), size)
	}
	return a, keys, packets, ctx
}

func BenchmarkAssemblyMaintenance(b *testing.B) {
	for _, size := range []int{100, 10000} {
		for _, sparse := range []bool{false, true} {
			b.Run(strconv.Itoa(size)+"/sparse="+strconv.FormatBool(sparse), func(b *testing.B) {
				a, keys, packets, ctx := benchmarkMaintenancePool(b, size)
				opt := FlushOptions{T: ctx.Timestamp.Add(time.Second)}
				b.ReportAllocs()
				b.ResetTimer()
				flushed, closed := 0, 0
				for i := 0; i < b.N; i++ {
					j := i % size
					packet := &packets[j]
					if sparse && i%100 == 0 {
						packet.Seq += uint32(len(packet.Payload))
					}
					a.AssembleWithContext(keys[j][0], packet, ctx)
					packet.Seq += uint32(len(packet.Payload))
					if i%100 == 99 {
						f, c := a.FlushWithOptions(opt)
						flushed += f
						closed += c
					}
				}
				b.StopTimer()
				want := 0
				if sparse {
					want = b.N / 100
				}
				if flushed != want || closed != 0 || len(a.connPool.conns) != size {
					b.Fatalf("flush totals = (%d, %d), want (%d, 0); pool size = %d", flushed, closed, want, len(a.connPool.conns))
				}
			})
		}
	}
}

func BenchmarkDueMaintenance(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		for _, stride := range []int{100, 1} {
			name := "sparse"
			if stride == 1 {
				name = "all"
			}
			b.Run(strconv.Itoa(size)+"/"+name, func(b *testing.B) {
				a, keys, packets, ctx := benchmarkMaintenancePool(b, size)
				opt := FlushOptions{T: ctx.Timestamp.Add(time.Second)}
				want := size / stride
				b.ReportAllocs()
				b.ResetTimer()
				b.StopTimer()
				for i := 0; i < b.N; i++ {
					// Rebuild real pending pages, not the pool, outside the timer.
					for j := 0; j < size; j += stride {
						packet := &packets[j]
						packet.Seq += uint32(len(packet.Payload))
						a.AssembleWithContext(keys[j][0], packet, ctx)
						packet.Seq += uint32(len(packet.Payload))
						c := a.connPool.conns[keys[j]]
						if c.c2s.first == nil || c.c2s.pages != 1 {
							b.Fatal("fixture did not queue one real page")
						}
					}
					b.StartTimer()
					f, c := a.FlushWithOptions(opt)
					b.StopTimer()
					if f != want || c != 0 || len(a.connPool.conns) != size {
						b.Fatalf("flush = (%d, %d), want (%d, 0); pool size = %d", f, c, want, len(a.connPool.conns))
					}
				}
			})
		}
	}
}
