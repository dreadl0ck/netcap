// Package aggregate provides private, bounded resident storage for capture state.
package aggregate

import (
	"container/list"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

type entry struct {
	key   string
	value []byte
	dirty bool
}

type Health struct {
	LimitBytes    int64  `json:"limitBytes"`
	ResidentBytes int64  `json:"residentBytes"`
	PeakBytes     int64  `json:"peakBytes"`
	DiskReads     uint64 `json:"diskReads"`
	DiskWrites    uint64 `json:"diskWrites"`
	Evictions     uint64 `json:"evictions"`
	DatabaseBytes int64  `json:"databaseBytes"`
}

// Store owns an ephemeral SQLite file. ResidentBytes charges encoded values,
// keys and 256 bytes per LRU entry; SQLite has a separate 1 MiB page cache.
// A caller's decoded record and serialization scratch are outside this cache.
type Store struct {
	mu     sync.Mutex
	db     *sql.DB
	tx     *sql.Tx
	path   string
	cache  map[string]*list.Element
	lru    list.List
	health Health
	err    error
	cancel func()
	closed bool
}

// Tx is valid only inside Do's callback. Callbacks must not call Store methods.
type Tx struct{ store *Store }

func Open(directory string, limit int64, cancel func()) (*Store, error) {
	if limit < 0 {
		return nil, fmt.Errorf("aggregate cache limit cannot be negative")
	}
	f, err := os.CreateTemp(directory, ".netcap-aggregate-*.sqlite")
	if err != nil {
		return nil, fmt.Errorf("create aggregate storage: %w", err)
	}
	path := f.Name()
	if err = f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	path = absolute
	s := &Store{path: path, cache: map[string]*list.Element{}, cancel: cancel, health: Health{LimitBytes: limit}}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := (&url.URL{Scheme: "file", Path: uriPath}).String()
	s.db, err = sql.Open("sqlite", uri)
	if err == nil {
		s.db.SetMaxOpenConns(1)
		_, err = s.db.Exec(`PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-1024; PRAGMA mmap_size=0; PRAGMA temp_store=FILE; CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID`)
	}
	if err == nil {
		s.tx, err = s.db.Begin()
	}
	if err != nil {
		if s.db != nil {
			_ = s.db.Close()
		}
		_ = os.Remove(path)
		return nil, fmt.Errorf("initialize aggregate storage: %w", err)
	}
	return s, nil
}

func charge(e *entry) int64 { return int64(len(e.key) + len(e.value) + 256) }

func (s *Store) fail(err error) error {
	if err != nil && s.err == nil {
		s.err = fmt.Errorf("aggregate state: %w", err)
		if s.cancel != nil {
			s.cancel()
		}
	}
	return s.err
}

func (s *Store) Do(fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("aggregate storage is closed")
	}
	if s.err != nil {
		return s.err
	}
	return s.fail(fn(&Tx{store: s}))
}

func (s *Store) write(e *entry) error {
	if !e.dirty {
		return nil
	}
	if _, err := s.tx.Exec(`INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, e.key, e.value); err != nil {
		return err
	}
	e.dirty = false
	s.health.DiskWrites++
	return nil
}

func (s *Store) remember(key string, value []byte, dirty bool) error {
	if element := s.cache[key]; element != nil {
		old := element.Value.(*entry)
		dirty = dirty || old.dirty
		s.health.ResidentBytes -= charge(old)
		s.lru.Remove(element)
		delete(s.cache, key)
	}
	e := &entry{key: key, value: value, dirty: dirty}
	cost := charge(e)
	if cost > s.health.LimitBytes {
		return s.write(e)
	}
	for s.health.ResidentBytes+cost > s.health.LimitBytes || len(s.cache) >= 4096 {
		oldest := s.lru.Back()
		old := oldest.Value.(*entry)
		if err := s.write(old); err != nil {
			return err
		}
		s.health.ResidentBytes -= charge(old)
		delete(s.cache, old.key)
		s.lru.Remove(oldest)
		s.health.Evictions++
	}
	s.cache[key] = s.lru.PushFront(e)
	s.health.ResidentBytes += cost
	s.health.PeakBytes = max(s.health.PeakBytes, s.health.ResidentBytes)
	return nil
}

func (t *Tx) Get(key string) ([]byte, bool, error) {
	s := t.store
	if element := s.cache[key]; element != nil {
		s.lru.MoveToFront(element)
		return append([]byte(nil), element.Value.(*entry).value...), true, nil
	}
	var value []byte
	err := s.tx.QueryRow(`SELECT value FROM state WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	s.health.DiskReads++
	if err = s.remember(key, value, false); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), value...), true, nil
}

func (t *Tx) Put(key string, value []byte) error {
	return t.store.remember(key, append([]byte(nil), value...), true)
}

func (t *Tx) Delete(prefix string) error {
	s := t.store
	if _, err := s.tx.Exec(`DELETE FROM state WHERE key>=? AND key<?`, prefix, prefixEnd(prefix)); err != nil {
		return err
	}
	for key, element := range s.cache {
		if strings.HasPrefix(key, prefix) {
			s.health.ResidentBytes -= charge(element.Value.(*entry))
			s.lru.Remove(element)
			delete(s.cache, key)
		}
	}
	return nil
}

func (t *Tx) Count(prefix string) (int64, error) {
	if err := t.flush(); err != nil {
		return 0, err
	}
	var count int64
	err := t.store.tx.QueryRow(`SELECT count(*) FROM state WHERE key>=? AND key<?`, prefix, prefixEnd(prefix)).Scan(&count)
	return count, err
}

func prefixEnd(prefix string) string { return prefix + "\xff" }

// Find selects the nearest key in prefix's range, optionally bounded above.
// It merges dirty cache entries with persisted rows without flushing the cache.
func (t *Tx) Find(prefix, upper string, descending bool) (string, []byte, bool, error) {
	s := t.store
	query := `SELECT key,value FROM state WHERE key>=? AND key<?`
	args := []any{prefix, prefixEnd(prefix)}
	if upper != "" {
		query += ` AND key<=?`
		args = append(args, upper)
	}
	if descending {
		query += ` ORDER BY key DESC LIMIT 1`
	} else {
		query += ` ORDER BY key LIMIT 1`
	}
	var key string
	var value []byte
	err := s.tx.QueryRow(query, args...).Scan(&key, &value)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", nil, false, err
	}
	for candidate, element := range s.cache {
		if !strings.HasPrefix(candidate, prefix) || upper != "" && candidate > upper {
			continue
		}
		if !found || descending && candidate > key || !descending && candidate < key || candidate == key {
			key, value, found = candidate, element.Value.(*entry).value, true
		}
	}
	return key, append([]byte(nil), value...), found, nil
}

func (t *Tx) flush() error {
	for element := t.store.lru.Back(); element != nil; element = element.Prev() {
		if err := t.store.write(element.Value.(*entry)); err != nil {
			return err
		}
	}
	return nil
}

// Each visits an ordered range with one row resident at a time. The callback may
// replace the same key; it must not add keys to the range being visited.
func (t *Tx) Each(prefix string, fn func(string, []byte) error) error {
	if err := t.flush(); err != nil {
		return err
	}
	last, first := prefix, true
	for {
		query := `SELECT key,value FROM state WHERE key>? AND key<? ORDER BY key LIMIT 1`
		if first {
			query = `SELECT key,value FROM state WHERE key>=? AND key<? ORDER BY key LIMIT 1`
		}
		var key string
		var value []byte
		err := t.store.tx.QueryRow(query, last, prefixEnd(prefix)).Scan(&key, &value)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if element := t.store.cache[key]; element != nil {
			value = append([]byte(nil), element.Value.(*entry).value...)
		}
		if err = fn(key, value); err != nil {
			return err
		}
		last, first = key, false
	}
}

func (s *Store) Error() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

func (s *Store) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health
	if info, err := os.Stat(s.path); err == nil {
		h.DatabaseBytes = info.Size()
	}
	return h
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.err
	}
	s.closed = true
	// This is scratch storage, not a recovery log. No capture state is reused.
	err := s.tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		err = nil
	}
	err = errors.Join(err, s.db.Close(), os.Remove(s.path))
	s.cache = nil
	s.lru.Init()
	s.health.ResidentBytes = 0
	return errors.Join(s.err, err)
}
