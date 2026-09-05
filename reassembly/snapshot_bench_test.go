package reassembly

import (
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func BenchmarkFlushWithOptions(b *testing.B) {
	for _, size := range []int{0, 100, 1000, 10000, 100000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			pool := &StreamPool{conns: make(map[key]*connection, size)}
			conns := make([]connection, size)
			now := time.Unix(1700000000, 0)
			opt := FlushOptions{T: now.Add(-time.Minute), TC: now.Add(-time.Minute)}
			for i := range conns {
				// Vary addresses, not just 16-bit ports, to keep large pools unique.
				src := []byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
				k := key{
					gopacket.NewFlow(layers.EndpointIPv4, src, []byte{192, 0, 2, 1}),
					gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x30, 0x39}, []byte{0, 80}),
				}
				conns[i].reset(&k, nil, now)
				pool.conns[k] = &conns[i]
			}
			if got := len(pool.conns); got != size {
				b.Fatalf("pool cardinality = %d, want %d", got, size)
			}

			// No pending pages or expired connections: no page cache or callbacks needed.
			a := &Assembler{connPool: pool}
			if flushed, closed := a.FlushWithOptions(opt); flushed != 0 || closed != 0 {
				b.Fatalf("warm flush = (%d, %d), want (0, 0)", flushed, closed)
			}
			if got := len(pool.conns); got != size {
				b.Fatalf("pool cardinality after warm flush = %d, want %d", got, size)
			}

			b.ReportAllocs()
			b.ResetTimer()
			var flushed, closed int
			for i := 0; i < b.N; i++ {
				f, c := a.FlushWithOptions(opt)
				flushed += f
				closed += c
			}
			b.StopTimer()

			if flushed != 0 || closed != 0 {
				b.Fatalf("flush totals = (%d, %d), want (0, 0)", flushed, closed)
			}
			if got := len(pool.conns); got != size {
				b.Fatalf("pool cardinality after timed flushes = %d, want %d", got, size)
			}
		})
	}
}
