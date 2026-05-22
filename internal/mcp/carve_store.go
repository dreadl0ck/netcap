/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CarveStore keeps carved sub-PCAPs around between MCP requests so the
// LLM can ask for their bytes via the netcap://carve/{id} resource URI.
//
// Entries are kept in memory; the on-disk copy (if any) lives under
// CarveStore.dir (defaults to os.TempDir()/netcap-mcp-carve).
//
// A trivial cap is enforced (maxEntries, maxAge) to prevent the LLM from
// unbounded carving from filling memory or disk. Eviction is FIFO by
// insertion time.
type CarveStore struct {
	mu         sync.Mutex
	dir        string
	maxEntries int
	maxAge     time.Duration
	entries    []*carveEntry
}

type carveEntry struct {
	ID         string
	Path       string // on-disk path (may be "")
	Bytes      []byte // in-memory copy (nil after expiry to free RAM)
	SizeBytes  int64
	SHA256     string
	Kind       string
	Source     string // download URL for reproducibility
	SessionID  string
	CreatedAt  time.Time
}

// NewCarveStore initialises a store; dir defaults when empty.
func NewCarveStore(dir string, maxEntries int, maxAge time.Duration) *CarveStore {
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "netcap-mcp-carve")
	}
	if maxEntries <= 0 {
		maxEntries = 32
	}
	if maxAge <= 0 {
		maxAge = 1 * time.Hour
	}
	_ = os.MkdirAll(dir, 0o700)
	return &CarveStore{
		dir:        dir,
		maxEntries: maxEntries,
		maxAge:     maxAge,
	}
}

// Put stores a carved PCAP and returns the canonical entry plus an MCP
// resource URI suitable for inclusion in tool responses.
func (c *CarveStore) Put(sessionID, kind, source string, body []byte) (*carveEntry, string, error) {
	if len(body) == 0 {
		return nil, "", errors.New("empty body")
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	filename := fmt.Sprintf("%s-%s.pcap", kind, id[:8])
	path := filepath.Join(c.dir, filename)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		// Fall back to memory-only if disk write fails.
		path = ""
	}
	entry := &carveEntry{
		ID:        id,
		Path:      path,
		Bytes:     body,
		SizeBytes: int64(len(body)),
		SHA256:    hex.EncodeToString(sum[:]),
		Kind:      kind,
		Source:    source,
		SessionID: sessionID,
		CreatedAt: time.Now(),
	}
	c.mu.Lock()
	c.entries = append(c.entries, entry)
	c.gcLocked()
	c.mu.Unlock()
	return entry, "netcap://carve/" + id, nil
}

// Get returns the entry for id, or nil if not found / evicted.
func (c *CarveStore) Get(id string) *carveEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// gcLocked enforces the size and age caps. Called with c.mu held.
func (c *CarveStore) gcLocked() {
	cutoff := time.Now().Add(-c.maxAge)
	kept := c.entries[:0]
	for _, e := range c.entries {
		if e.CreatedAt.Before(cutoff) {
			c.removeFile(e)
			continue
		}
		kept = append(kept, e)
	}
	for len(kept) > c.maxEntries {
		c.removeFile(kept[0])
		kept = kept[1:]
	}
	c.entries = kept
}

func (c *CarveStore) removeFile(e *carveEntry) {
	if e.Path != "" {
		_ = os.Remove(e.Path)
	}
	e.Bytes = nil
}

// Stats returns counters useful for observability and tests.
func (c *CarveStore) Stats() (count int, totalBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		count++
		totalBytes += e.SizeBytes
	}
	return count, totalBytes
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
