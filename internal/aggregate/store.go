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
	LimitBytes         int64  `json:"limitBytes"`
	ResidentBytes      int64  `json:"residentBytes"`
	PeakBytes          int64  `json:"peakBytes"`
	DiskReads          uint64 `json:"diskReads"`
	DiskWrites         uint64 `json:"diskWrites"`
	Evictions          uint64 `json:"evictions"`
	DatabaseBytes      int64  `json:"databaseBytes"`
	PreparedStatements uint64 `json:"preparedStatements"`
}

// Store owns an ephemeral SQLite file. ResidentBytes charges encoded values,
// keys and 256 bytes per LRU entry; SQLite has a separate 1 MiB page cache.
// A caller's decoded record and serialization scratch are outside this cache.
type Store struct {
	mu         sync.Mutex
	db         *sql.DB
	tx         *sql.Tx
	path       string
	cache      map[string]*list.Element
	dirty      map[string]*entry
	lru        list.List
	health     Health
	err        error
	cancel     func()
	closed     bool
	statements map[string]*sql.Stmt
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
	s := &Store{path: path, cache: map[string]*list.Element{}, dirty: map[string]*entry{}, statements: map[string]*sql.Stmt{}, cancel: cancel, health: Health{LimitBytes: limit}}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := (&url.URL{Scheme: "file", Path: uriPath}).String()
	s.db, err = sql.Open("sqlite", uri)
	if err == nil {
		s.db.SetMaxOpenConns(1)
		_, err = s.db.Exec(`PRAGMA page_size=16384; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-1024; PRAGMA mmap_size=0; PRAGMA temp_store=FILE; CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID`)
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

func charge(e *entry) int64 { return entryCharge(e.key, e.value) }

func entryCharge(key string, value []byte) int64 { return int64(len(key) + len(value) + 256) }

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
	statement, err := s.statement(`INSERT INTO state(key,value) VALUES(?,coalesce(?,x'')) ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
	if err != nil {
		return err
	}
	if _, err := statement.Exec(e.key, e.value); err != nil {
		return err
	}
	e.dirty = false
	delete(s.dirty, e.key)
	s.health.DiskWrites++
	return nil
}

// All callers hold mu. Query text comes only from the fixed internal SQL shapes.
func (s *Store) statement(query string) (*sql.Stmt, error) {
	if statement := s.statements[query]; statement != nil {
		return statement, nil
	}
	statement, err := s.tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	s.statements[query] = statement
	s.health.PreparedStatements++
	return statement, nil
}

func (s *Store) remember(key string, value []byte, dirty bool) error {
	if element := s.cache[key]; element != nil {
		old := element.Value.(*entry)
		dirty = dirty || old.dirty
		s.health.ResidentBytes -= charge(old)
		s.lru.Remove(element)
		delete(s.cache, key)
		delete(s.dirty, key)
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
	if dirty {
		s.dirty[key] = e
	}
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
	statement, err := s.statement(`SELECT value FROM state WHERE key=?`)
	if err != nil {
		return nil, false, err
	}
	err = statement.QueryRow(key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	s.health.DiskReads++
	if len(value) != 0 && entryCharge(key, value) > s.health.LimitBytes {
		// Scan into []byte already gives the caller an owned copy.
		return value, true, nil
	}
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
	statement, err := s.statement(`DELETE FROM state WHERE key>=? AND key<?`)
	if err != nil {
		return err
	}
	if _, err := statement.Exec(prefix, prefixEnd(prefix)); err != nil {
		return err
	}
	for key, element := range s.cache {
		if strings.HasPrefix(key, prefix) {
			s.health.ResidentBytes -= charge(element.Value.(*entry))
			s.lru.Remove(element)
			delete(s.cache, key)
			delete(s.dirty, key)
		}
	}
	return nil
}

func (t *Tx) DeleteKey(key string) error {
	s := t.store
	statement, err := s.statement(`DELETE FROM state WHERE key=?`)
	if err != nil {
		return err
	}
	if _, err := statement.Exec(key); err != nil {
		return err
	}
	if element := s.cache[key]; element != nil {
		s.health.ResidentBytes -= charge(element.Value.(*entry))
		s.lru.Remove(element)
		delete(s.cache, key)
		delete(s.dirty, key)
	}
	return nil
}

func (t *Tx) Count(prefix string) (int64, error) {
	if err := t.flush(); err != nil {
		return 0, err
	}
	var count int64
	statement, err := t.store.statement(`SELECT count(*) FROM state WHERE key>=? AND key<?`)
	if err != nil {
		return 0, err
	}
	err = statement.QueryRow(prefix, prefixEnd(prefix)).Scan(&count)
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
	statement, err := s.statement(query)
	if err != nil {
		return "", nil, false, err
	}
	err = statement.QueryRow(args...).Scan(&key, &value)
	found := err == nil
	if found {
		s.health.DiskReads++
	}
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
	for _, entry := range t.store.dirty {
		if err := t.store.write(entry); err != nil {
			return err
		}
	}
	return nil
}

// Next returns one ordered row after flushing pending writes. An empty after
// starts at prefix. Callers can release Do's lock between successive records.
func (t *Tx) Next(prefix, after string) (string, []byte, bool, error) {
	if err := t.flush(); err != nil {
		return "", nil, false, err
	}
	query := `SELECT key,value FROM state WHERE key>? AND key<? ORDER BY key LIMIT 1`
	if after == "" {
		after = prefix
		query = `SELECT key,value FROM state WHERE key>=? AND key<? ORDER BY key LIMIT 1`
	}
	var key string
	var value []byte
	statement, err := t.store.statement(query)
	if err != nil {
		return "", nil, false, err
	}
	err = statement.QueryRow(after, prefixEnd(prefix)).Scan(&key, &value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	t.store.health.DiskReads++
	return key, value, true, nil
}

func (t *Tx) Last(prefix string) (string, []byte, bool, error) {
	if err := t.flush(); err != nil {
		return "", nil, false, err
	}
	var key string
	var value []byte
	statement, err := t.store.statement(`SELECT key,value FROM state WHERE key>=? AND key<? ORDER BY key DESC LIMIT 1`)
	if err != nil {
		return "", nil, false, err
	}
	err = statement.QueryRow(prefix, prefixEnd(prefix)).Scan(&key, &value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	t.store.health.DiskReads++
	return key, value, true, nil
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
		statement, err := t.store.statement(query)
		if err != nil {
			return err
		}
		err = statement.QueryRow(last, prefixEnd(prefix)).Scan(&key, &value)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		t.store.health.DiskReads++
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
	var statementError error
	for _, statement := range s.statements {
		statementError = errors.Join(statementError, statement.Close())
	}
	s.statements = nil
	// This is scratch storage, not a recovery log. No capture state is reused.
	err := s.tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		err = nil
	}
	err = errors.Join(statementError, err, s.db.Close(), os.Remove(s.path))
	s.cache = nil
	s.dirty = nil
	s.lru.Init()
	s.health.ResidentBytes = 0
	return errors.Join(s.err, err)
}
