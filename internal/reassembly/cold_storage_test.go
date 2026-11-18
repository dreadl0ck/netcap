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
