package aggregate

import (
	"bytes"
	"fmt"
	"testing"
)

func TestBoundedBatchesPreserveOrderAndOversizedProgress(t *testing.T) {
	s, err := Open(t.TempDir(), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Do(func(tx *Tx) error {
		for i := 0; i < 70; i++ {
			n := 100
			if i == 33 {
				n = BatchBytes + 1
			}
			if err := tx.Put(fmt.Sprintf("row/%03d", i), bytes.Repeat([]byte{byte(i)}, n)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	last := ""
	count := 0
	for {
		var rows []Row
		if err := s.Do(func(tx *Tx) error { var err error; rows, err = tx.NextBatch("row/", last); return err }); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		if len(rows) > BatchRows {
			t.Fatal("row bound exceeded")
		}
		bytes := 0
		for _, row := range rows {
			if row.Key != fmt.Sprintf("row/%03d", count) || len(row.Value) == 0 || row.Value[0] != byte(count) {
				t.Fatal("batch lost ordering or bytes", row.Key, count)
			}
			count++
			last = row.Key
			bytes += len(row.Key) + len(row.Value) + 64
		}
		if len(rows) > 1 && bytes > BatchBytes {
			t.Fatal("batch byte bound exceeded", bytes)
		}
	}
	if count != 70 {
		t.Fatal("batch traversal lost rows", count)
	}
}
