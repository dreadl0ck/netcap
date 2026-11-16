package aggregate

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestStableRangesAllowCurrentUpdatesAndNestedReads(t *testing.T) {
	s, err := Open(t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Do(func(tx *Tx) error {
		if err := tx.Put("lookup/value", []byte("lookup")); err != nil {
			return err
		}
		for i := range 100 {
			value := []byte(fmt.Sprint(i))
			if i == 32 {
				value = bytes.Repeat([]byte{42}, BatchBytes+1)
			}
			if err := tx.Put(fmt.Sprintf("rows/%03d", i), value); err != nil {
				return err
			}
		}
		count := 0
		if err := tx.EachStable("rows/", func(key string, value []byte) error {
			if key != fmt.Sprintf("rows/%03d", count) {
				t.Fatalf("out-of-order row %q at %d", key, count)
			}
			if count == 32 && len(value) != BatchBytes+1 {
				t.Fatal("oversized row was lost")
			}
			count++
			if err := tx.EachStable("lookup/", func(_ string, data []byte) error {
				if string(data) != "lookup" {
					t.Fatal("nested range changed")
				}
				return nil
			}); err != nil {
				return err
			}
			return tx.Put(key, []byte("updated"))
		}); err != nil {
			return err
		}
		if count != 100 {
			t.Fatal("range lost rows", count)
		}
		return tx.Each("rows/", func(_ string, value []byte) error {
			if string(value) != "updated" {
				t.Fatal("current-row update was lost")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMutableRangeRetainsFutureMutationVisibility(t *testing.T) {
	s, err := Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Do(func(tx *Tx) error {
		for _, key := range []string{"rows/a", "rows/b", "rows/c"} {
			if err := tx.Put(key, []byte("old")); err != nil {
				return err
			}
		}
		visited := []string{}
		err := tx.Each("rows/", func(key string, value []byte) error {
			visited = append(visited, key)
			if key == "rows/a" {
				if err := tx.Put("rows/b", []byte("new")); err != nil {
					return err
				}
				return tx.DeleteKey("rows/c")
			}
			if key == "rows/b" && string(value) != "new" {
				t.Fatal("future row update became stale")
			}
			return nil
		})
		if len(visited) != 2 {
			t.Fatal("future deletion became stale", visited)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStableRangePropagatesCallbackFailure(t *testing.T) {
	s, err := Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	failure := errors.New("stop export")
	visits := 0
	err = s.Do(func(tx *Tx) error {
		for i := range 100 {
			if err := tx.Put(fmt.Sprintf("rows/%03d", i), []byte("value")); err != nil {
				return err
			}
		}
		return tx.EachStable("rows/", func(string, []byte) error { visits++; return failure })
	})
	if !errors.Is(err, failure) || visits != 1 {
		t.Fatal("callback failure did not stop range", visits, err)
	}
}

func TestStableRangeMakesProgressAfterOversizedEmptyKey(t *testing.T) {
	s, err := Open(t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Do(func(tx *Tx) error {
		if err := tx.Put("", bytes.Repeat([]byte{1}, BatchBytes+1)); err != nil {
			return err
		}
		if err := tx.Put("z", []byte("last")); err != nil {
			return err
		}
		keys := []string{}
		err := tx.EachStable("", func(key string, _ []byte) error {
			keys = append(keys, key)
			if len(keys) > 2 {
				return errors.New("empty key repeated")
			}
			return nil
		})
		if len(keys) != 2 || keys[0] != "" || keys[1] != "z" {
			t.Fatalf("range progress: %q", keys)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
