package reassembly

import (
	"strconv"
	"testing"
	"time"
)

func BenchmarkFlushWithOptions(b *testing.B) {
	for _, size := range []int{0, 100, 1000, 10000, 100000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			pool := &StreamPool{conns: make(map[key]*connection, size), nextAlloc: 128, factory: &testFactoryBench{}}
			now := time.Unix(1700000000, 0)
			opt := FlushOptions{T: now.Add(-time.Minute), TC: now.Add(-time.Minute)}
			for i := 0; i < size; i++ {
				k := snapshotKey(i)
				pool.getConnection(&k, false, now, nil)
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
