package reassembly

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
)

func TestColdDeadlineRejectsInconsistentIndex(t *testing.T) {
	canceled := false
	store, err := aggregate.Open(t.TempDir(), 2048, func() { canceled = true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	pool := NewStreamPool(new(flushProgressFactory))
	pool.cold = &coldStorage{state: store, prefix: "fixture/"}
	key := snapshotKey(1)
	snap := coldConnection{Version: 1, ObserveClose: true}
	seen := time.Unix(2, 0)
	for i := range snap.Halves {
		snap.Halves[i].LastSeen = SaveTime(seen)
	}
	for i := range snap.Key {
		snap.Key[i] = SaveFlow(key[i])
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	id := coldID(&key)
	if err := store.Do(func(tx *aggregate.Tx) error {
		if err := tx.Put(pool.cold.row(id), wire); err != nil {
			return err
		}
		return tx.Put("fixture/due/closed/8000000000000001/00000000/"+id+"/", []byte(id))
	}); err != nil {
		t.Fatal(err)
	}
	if got := pool.flushColdDue(FlushOptions{TC: seen.Add(-time.Nanosecond)}); got != 0 {
		t.Fatalf("closed %d connections from an inconsistent deadline", got)
	}
	if err := store.Error(); err == nil || !strings.Contains(err.Error(), "cold deadline entry does not match") || !canceled {
		t.Fatalf("expected fatal storage error before the cutoff check: %v, canceled=%t", err, canceled)
	}
}

func TestColdEOFFailsOnMissingOrderEntry(t *testing.T) {
	canceled := false
	store, err := aggregate.Open(t.TempDir(), 2048, func() { canceled = true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	pool := NewStreamPool(new(flushProgressFactory))
	pool.cold = &coldStorage{state: store, prefix: "fixture/"}
	k := snapshotKey(1)
	snap := coldConnection{Version: 1}
	for i := range k {
		snap.Key[i] = SaveFlow(k[i])
	}
	order, err := coldOrder(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Do(func(tx *aggregate.Tx) error {
		if err := pool.cold.put(tx, coldID(&k), snap, false); err != nil {
			return err
		}
		return tx.DeleteKey(pool.cold.prefix + "order/" + order + "/")
	}); err != nil {
		t.Fatal(err)
	}
	pool.cold.count.Store(1)
	a := NewAssembler(pool)
	defer a.Release()
	if n := a.FlushAll(); n != 0 {
		t.Fatalf("finalized %d connections with a missing order entry", n)
	}
	if err := store.Error(); err == nil || !strings.Contains(err.Error(), "order index ended after 0 entries, want 1") || !canceled {
		t.Fatalf("expected fatal storage cancellation, got %v, canceled=%t", err, canceled)
	}
}

func TestColdFinalizationRejectsMismatchedStateRow(t *testing.T) {
	for _, path := range []string{"EOF", "expiry", "cleanup"} {
		t.Run(path, func(t *testing.T) {
			canceled := false
			store, err := aggregate.Open(t.TempDir(), 2048, func() { canceled = true })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			pool := NewStreamPool(new(flushProgressFactory))
			pool.cold = &coldStorage{state: store, prefix: "fixture/"}
			k, wrong := snapshotKey(1), snapshotKey(2)
			snap := coldConnection{Version: 1, ObserveClose: true}
			for i := range k {
				snap.Key[i] = SaveFlow(k[i])
			}
			if err := store.Do(func(tx *aggregate.Tx) error {
				return pool.cold.put(tx, coldID(&wrong), snap, false)
			}); err != nil {
				t.Fatal(err)
			}
			pool.cold.count.Store(1)
			var n int
			switch path {
			case "EOF":
				a := NewAssembler(pool)
				defer a.Release()
				n = a.FlushAll()
			case "expiry":
				n = pool.flushColdDue(FlushOptions{TC: time.Unix(1, 0)})
			case "cleanup":
				n = pool.flushColdAll(true)
			}
			if n != 0 || pool.cold.count.Load() != 1 {
				t.Fatalf("finalized %d connections from a mismatched state row", n)
			}
			if err := store.Error(); err == nil || !strings.Contains(err.Error(), "row ID does not match") || !canceled {
				t.Fatalf("expected fatal storage cancellation, got %v, canceled=%t", err, canceled)
			}
		})
	}
}

func TestColdEOFFailsOnMismatchedOrderEntry(t *testing.T) {
	canceled := false
	store, err := aggregate.Open(t.TempDir(), 2048, func() { canceled = true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	pool := NewStreamPool(new(flushProgressFactory))
	pool.cold = &coldStorage{state: store, prefix: "fixture/"}
	k := snapshotKey(1)
	var snap coldConnection
	snap.Version = 1
	for i := range k {
		snap.Key[i] = SaveFlow(k[i])
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	id := coldID(&k)
	if err := store.Do(func(tx *aggregate.Tx) error {
		if err := tx.Put(pool.cold.row(id), wire); err != nil {
			return err
		}
		return tx.Put("fixture/order/00/", []byte(id))
	}); err != nil {
		t.Fatal(err)
	}
	a := NewAssembler(pool)
	defer a.Release()
	if n := a.FlushAll(); n != 0 {
		t.Fatalf("finalized %d connections from an inconsistent index", n)
	}
	if err := store.Error(); err == nil || !strings.Contains(err.Error(), "cold order entry does not match") || !canceled {
		t.Fatalf("expected a fatal storage error and cancellation, got %v, canceled=%t", err, canceled)
	}
}

func TestColdRestoreRejectsMismatchedLookupKey(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "forward"
		if reverse {
			name = "reverse"
		}
		t.Run(name, func(t *testing.T) {
			canceled := false
			store, err := aggregate.Open(t.TempDir(), 2048, func() { canceled = true })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			pool := NewStreamPool(new(flushProgressFactory))
			pool.cold = &coldStorage{state: store, prefix: "fixture/"}
			lookup, other := snapshotKey(1), snapshotKey(2)
			storedAt := lookup
			if reverse {
				storedAt = lookup.reverse()
			}
			snap := coldConnection{Version: 1}
			for i := range other {
				snap.Key[i] = SaveFlow(other[i])
			}
			wire, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Do(func(tx *aggregate.Tx) error {
				return tx.Put(pool.cold.row(coldID(&storedAt)), wire)
			}); err != nil {
				t.Fatal(err)
			}
			ref, reversed, found, err := pool.restoreCold(&lookup)
			if ref.conn != nil || !found || reversed != reverse || err == nil || !strings.Contains(err.Error(), "does not match lookup key") {
				t.Fatalf("unexpected restore result: %v %t %t %v", ref, reversed, found, err)
			}
			if store.Error() == nil || !canceled || len(pool.conns) != 0 {
				t.Fatal("mismatch did not fail storage before materializing a connection")
			}
		})
	}
}
