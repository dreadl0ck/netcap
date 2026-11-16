package aggregate

import (
	"fmt"
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
