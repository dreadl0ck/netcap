package aggregate

import (
	"fmt"
	"runtime/metrics"
	"testing"
)

func TestPreparedStatementsDoNotScaleWithRows(t *testing.T) {
	s, err := Open(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for pass := 0; pass < 2; pass++ {
		if err := s.Do(func(tx *Tx) error {
			for i := 0; i < 1000; i++ {
				if err := tx.Put(fmt.Sprintf("rows/%06d", i), []byte("value")); err != nil {
					return err
				}
			}
			last := ""
			for i := 0; i < 1000; i++ {
				key, _, found, err := tx.Next("rows/", last)
				if err != nil {
					return err
				}
				if !found {
					return fmt.Errorf("missing row %d", i)
				}
				last = key
				if _, ok, err := tx.Get(key); err != nil {
					return err
				} else if !ok {
					return fmt.Errorf("missing point lookup")
				}
			}
			if _, _, found, err := tx.Next("rows/", last); err != nil || found {
				return fmt.Errorf("invalid terminal row: %v", err)
			}
			return tx.Each("rows/", func(key string, value []byte) error { return tx.Put(key, value) })
		}); err != nil {
			t.Fatal(err)
		}
		if got := s.Health().PreparedStatements; got != 4 {
			t.Fatalf("prepared %d statements for repeated point/range operations, want 4", got)
		}
	}
	statements := s.statements
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err := statement.Exec("unused"); err == nil {
			t.Fatal("statement survived store teardown")
		}
	}
}

func TestQueriesDoNotSpawnGoroutines(t *testing.T) {
	s, err := Open(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	created := func() uint64 {
		sample := []metrics.Sample{{Name: "/sched/goroutines-created:goroutines"}}
		metrics.Read(sample)
		return sample[0].Value.Uint64()
	}
	var before uint64
	if err := s.Do(func(tx *Tx) error {
		for i := 0; i < 64; i++ {
			if err := tx.Put(fmt.Sprintf("rows/%06d", i), []byte("value")); err != nil {
				return err
			}
		}
		if _, err := tx.NextBatch("rows/", ""); err != nil {
			return err
		}
		before = created()
		for i := 0; i < 200; i++ {
			if _, err := tx.NextBatch("rows/", ""); err != nil {
				return err
			}
			if _, _, err := tx.Get(fmt.Sprintf("rows/%06d", i%64)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if spawned := created() - before; spawned > 20 {
		t.Fatalf("200 reads spawned %d goroutines; each wakes an OS thread", spawned)
	}
}
