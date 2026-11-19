package aggregate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBoundedStoreEvictionAndOrderedUpdates(t *testing.T) {
	s, err := Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	value := bytes.Repeat([]byte("x"), 100)
	for i := 0; i < 1000; i++ {
		if err = s.Do(func(tx *Tx) error { return tx.Put(fmt.Sprintf("a/%04d", i), value) }); err != nil {
			t.Fatal(err)
		}
	}
	value[0] = 'z'
	if h := s.Health(); h.PeakBytes > h.LimitBytes || h.Evictions < 900 || h.DiskWrites < 900 {
		t.Fatal(h)
	}
	if err = s.Do(func(tx *Tx) error {
		for _, key := range []string{"a/0000", "a/0999"} {
			value, ok, err := tx.Get(key)
			if err != nil || !ok || value[0] != 'x' {
				return fmt.Errorf("lost or aliased %s: %v", key, err)
			}
			value[0] = 'y'
			other, _, err := tx.Get(key)
			if err != nil || other[0] != 'x' {
				return fmt.Errorf("Get leaked mutable cached bytes")
			}
		}
		n := 0
		return tx.Each("a/", func(key string, value []byte) error {
			if key != fmt.Sprintf("a/%04d", n) || len(value) != 100 {
				return fmt.Errorf("incorrect order/value at %d", n)
			}
			n++
			if err := tx.Put(key, []byte("updated")); err != nil {
				return err
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Do(func(tx *Tx) error {
		n := 0
		if err := tx.Each("a/", func(_ string, value []byte) error {
			n++
			if string(value) != "updated" {
				return fmt.Errorf("snapshot update was lost")
			}
			return nil
		}); err != nil {
			return err
		}
		if n != 1000 {
			return fmt.Errorf("visited %d/1000 records", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkOversizedDiskGet(b *testing.B) {
	s, err := Open(b.TempDir(), 1024, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	payload := bytes.Repeat([]byte{'x'}, 64<<10)
	if err := s.Do(func(tx *Tx) error { return tx.Put("oversized", payload) }); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if err := s.Do(func(tx *Tx) error {
			value, ok, err := tx.Get("oversized")
			if err != nil || !ok || len(value) != len(payload) || value[0] != 'x' {
				return fmt.Errorf("oversized value changed: %v", err)
			}
			value[0] = 'y'
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestStoreRangeFindMergesDirtyAndPersistedRows(t *testing.T) {
	s, err := Open(t.TempDir(), 600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.Do(func(tx *Tx) error {
		for _, key := range []string{"h/a/010", "h/a/030", "h/b/090"} {
			if err := tx.Put(key, []byte(key)); err != nil {
				return err
			}
		}
		if err := tx.Put("h/a/020", []byte("dirty")); err != nil {
			return err
		}
		for _, tc := range []struct {
			prefix, upper, want string
			desc                bool
		}{
			{"h/a/", "h/a/025", "h/a/020", true},
			{"h/a/", "", "h/a/030", true},
			{"h/a/", "", "h/a/010", false},
			{"h/a/", "h/a/005", "", true},
		} {
			key, _, found, err := tx.Find(tc.prefix, tc.upper, tc.desc)
			if err != nil || key != tc.want || found != (tc.want != "") {
				return fmt.Errorf("Find %+v: %q %v %v", tc, key, found, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStoreConcurrentReadModifyWrite(t *testing.T) {
	s, err := Open(t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if err := s.Do(func(tx *Tx) error {
					value, found, err := tx.Get("counter")
					if err != nil {
						return err
					}
					n := 0
					if found {
						n, err = strconv.Atoi(string(value))
						if err != nil {
							return err
						}
					}
					return tx.Put("counter", []byte(strconv.Itoa(n+1)))
				}); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	if err = s.Do(func(tx *Tx) error {
		value, _, err := tx.Get("counter")
		if err == nil && string(value) != "800" {
			return fmt.Errorf("counter=%s", value)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if s.Health().ResidentBytes != 0 {
		t.Fatal("zero cache retained bytes")
	}
}

func TestStorePrivateScratchCleanupAndFailureCancellation(t *testing.T) {
	var cancelled atomic.Int32
	s, err := Open(t.TempDir(), 1024, func() { cancelled.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.path)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("scratch permissions: %v %v", info, err)
	}
	if _, err = Open(t.TempDir(), -1, nil); err == nil {
		t.Fatal("negative limit accepted")
	}
	if err = s.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Do(func(tx *Tx) error { _, _, err := tx.Get("missing"); return err }); err == nil {
			t.Fatal("failed storage was silently accepted")
		}
	}
	if cancelled.Load() != 1 {
		t.Fatal("failure did not cancel exactly once")
	}
	if err = s.Close(); err == nil {
		t.Fatal("Close lost original storage failure")
	}
	if _, err = os.Stat(s.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private scratch survived Close", err)
	}
	if err = s.Do(func(*Tx) error { return nil }); err == nil {
		t.Fatal("closed store accepted operation")
	}
}

func TestStoreDeleteClearsCachedAndPersistedNamespace(t *testing.T) {
	s, err := Open(t.TempDir(), 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Do(func(tx *Tx) error {
		for _, key := range []string{"connection/old", "other/keep", "connection/new"} {
			if err := tx.Put(key, []byte("value")); err != nil {
				return err
			}
		}
		if err := tx.Delete("connection/"); err != nil {
			return err
		}
		count, err := tx.Count("")
		if err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("remaining records=%d, want 1", count)
		}
		_, ok, err := tx.Get("other/keep")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("unrelated namespace was deleted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRelativeDirectoryWithURICharacters(t *testing.T) {
	t.Chdir(t.TempDir())
	directory := "capture # evidence"
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(directory, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(s.path) {
		t.Fatal("scratch path depends on later working-directory changes")
	}
	if err = s.Do(func(tx *Tx) error {
		if err := tx.Put("key", []byte("value")); err != nil {
			return err
		}
		value, ok, err := tx.Get("key")
		if err != nil {
			return err
		}
		if !ok || string(value) != "value" {
			return errors.New("relative-path backing store lost data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreEmptyValuesAndExactDeletion(t *testing.T) {
	s, err := Open(t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Do(func(tx *Tx) error {
		for _, key := range []string{"a/1", "a/10", "a/100"} {
			if err := tx.Put(key, nil); err != nil {
				return err
			}
		}
		if err := tx.DeleteKey("a/1"); err != nil {
			return err
		}
		for _, key := range []string{"a/10", "a/100"} {
			value, found, err := tx.Get(key)
			if err != nil {
				return err
			}
			if !found || len(value) != 0 {
				return errors.New("empty value or adjacent key lost")
			}
		}
		key, _, found, err := tx.Last("a/")
		if err != nil {
			return err
		}
		if !found || key != "a/100" {
			return fmt.Errorf("last key=%q found=%v", key, found)
		}
		key, _, found, err = tx.Next("a/", "")
		if err != nil {
			return err
		}
		if !found || key != "a/10" {
			return fmt.Errorf("first key=%q found=%v", key, found)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
