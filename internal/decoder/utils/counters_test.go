package utils

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestAtomicCounterMapSnapshot(t *testing.T) {
	counter := NewAtomicCounterMap()
	if got := counter.Snapshot(); len(got) != 0 {
		t.Fatalf("empty snapshot = %v", got)
	}
	counter.Inc("TCP")
	counter.Inc("TCP")
	counter.Inc("UDP")
	want := map[string]int64{"TCP": 2, "UDP": 1}
	if got := counter.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %v, want %v", got, want)
	}
	snapshot := counter.Snapshot()
	snapshot["TCP"] = -1
	if !reflect.DeepEqual(counter.Items, want) {
		t.Fatalf("snapshot changed root Items: %v", counter.Items)
	}
	shard := counter.NewShard()
	shard.Inc("TCP")
	shard.Inc("Payload")
	want = map[string]int64{"TCP": 3, "UDP": 1, "Payload": 1}
	if got := counter.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sharded snapshot = %v, want %v", got, want)
	}
}

func TestAtomicCounterMapConcurrentShards(t *testing.T) {
	const workers, increments = 8, 1000
	counter := NewAtomicCounterMap()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range workers + 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			local := counter
			if i != workers {
				local = counter.NewShard()
			}
			key := fmt.Sprint(i)
			for range increments {
				local.Inc("shared")
				local.Inc(key)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	close(start)
	previous := map[string]int64{}
	for {
		snapshot := counter.Snapshot()
		for k, v := range previous {
			if snapshot[k] < v {
				t.Fatalf("count for %q decreased: %d < %d", k, snapshot[k], v)
			}
		}
		previous = snapshot
		select {
		case <-done:
			want := map[string]int64{"shared": (workers + 1) * increments}
			for i := range workers + 1 {
				want[fmt.Sprint(i)] = increments
			}
			if got := counter.Snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("final snapshot = %v, want %v", got, want)
			}
			return
		default:
		}
	}
}
