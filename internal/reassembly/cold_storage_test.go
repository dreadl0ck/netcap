package reassembly

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/aggregate"
)

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
