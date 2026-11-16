package aggregate

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMarkSeenIsAtomicAcrossEvictionAndReset(t *testing.T) {
	state, err := Open(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	var fresh atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			seen, err := state.MarkSeen("seen/shared")
			if err != nil {
				t.Error(err)
				return
			}
			if !seen {
				fresh.Add(1)
			}
		})
	}
	wg.Wait()
	if fresh.Load() != 1 {
		t.Fatal("concurrent first observations", fresh.Load())
	}
	for i := range 1000 {
		key := fmt.Sprintf("seen/%04d", i)
		if seen, err := state.MarkSeen(key); err != nil || seen {
			t.Fatal(key, seen, err)
		}
	}
	if seen, err := state.MarkSeen("seen/shared"); err != nil || !seen {
		t.Fatal("eviction lost a seen key", seen, err)
	}
	if err := state.Do(func(tx *Tx) error { return tx.Delete("seen/") }); err != nil {
		t.Fatal(err)
	}
	if seen, err := state.MarkSeen("seen/shared"); err != nil || seen {
		t.Fatal("reset retained a seen key", seen, err)
	}
	if state.Health().PeakBytes > 1 || state.Health().DiskWrites < 1000 {
		t.Fatal(state.Health())
	}
}
