package reassembly

import (
	"fmt"
	"testing"
)

var pageCacheInitializationSink []*pageCache

func BenchmarkPageCacheInitialization(b *testing.B) {
	for _, workers := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				caches := make([]*pageCache, workers)
				for worker := range caches {
					caches[worker] = newPageCache()
				}
				pageCacheInitializationSink = caches
			}
		})
	}
}
