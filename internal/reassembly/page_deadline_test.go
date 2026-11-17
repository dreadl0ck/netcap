package reassembly

import (
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestQueuedPageDeadlinesSurviveArbitraryRemoval(t *testing.T) {
	var half halfconnection
	pc := newPageCache()
	pages := make([]*page, 4096)
	base := time.Unix(1700000000, 0)
	for i := range pages {
		pages[i] = pc.next(base.Add(time.Duration(len(pages)-i)*time.Second), 1)
		half.queueDeadline(pages[i])
	}
	order := rand.New(rand.NewSource(7)).Perm(len(pages))
	for _, index := range order {
		pc.replace(pages[index])
		pages[index] = nil
		var want time.Time
		for _, p := range pages {
			if p != nil && (want.IsZero() || p.seen.Before(want)) {
				want = p.seen
			}
		}
		got, present := half.pendingDeadline()
		if present != !want.IsZero() || !got.Equal(want) {
			t.Fatal("queued minimum changed", got, want)
		}
	}
	if len(*half.pageDeadlines) != 0 || cap(*half.pageDeadlines) != 0 {
		t.Fatal("empty queue retained page references")
	}
}

func TestQueuedPageLeavesIndexOnDeliveryAndReuse(t *testing.T) {
	var half halfconnection
	pc := newPageCache()
	p := pc.next(time.Unix(1, 0), 1)
	half.queueDeadline(p)
	p.convertToPages(pc, 0, nil)
	if _, present := half.pendingDeadline(); present {
		t.Fatal("saved page remained pending")
	}
	pc.replace(p)
	reused := pc.next(time.Unix(2, 0), 1)
	if reused.deadlines != nil || reused.deadlinePosition != 0 {
		t.Fatal("recycled page retained queue membership")
	}
	pc.replace(reused)
}

func BenchmarkQueuedDeadlineRefresh(b *testing.B) {
	for _, n := range []int{1, 1024, 65536} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			pool := &StreamPool{}
			conn := &connection{live: true}
			base := time.Unix(1, 0)
			for i := range n {
				p := &page{seen: base.Add(time.Duration(n - i))}
				conn.c2s.queueDeadline(p)
				if conn.c2s.first == nil {
					conn.c2s.first = p
				}
			}
			pool.refreshDueLocked(conn, false)
			b.ResetTimer()
			for range b.N {
				pool.refreshDueLocked(conn, false)
			}
		})
	}
}
