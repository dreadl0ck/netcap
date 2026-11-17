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
	maxBytes   int64
	maxAge     time.Duration
	entries    []*carveEntry
}

type carveEntry struct {
	ID        string
	Path      string // on-disk path (may be "")
	Bytes     []byte // in-memory copy (nil after expiry to free RAM)
	SizeBytes int64
	SHA256    string
	Kind      string
	Source    string // download URL for reproducibility
	SessionID string
	CreatedAt time.Time
	MIMEType  string
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
		maxBytes:   64 << 20,
		maxAge:     maxAge,
	}
}

// Put stores a carved PCAP and returns the canonical entry plus an MCP
// resource URI suitable for inclusion in tool responses.
func (c *CarveStore) Put(sessionID, kind, source string, body []byte) (*carveEntry, string, error) {
	return c.PutTyped(sessionID, kind, source, "application/vnd.tcpdump.pcap", body)
}

func (c *CarveStore) PutTyped(sessionID, kind, source, mime string, body []byte) (*carveEntry, string, error) {
	if len(body) == 0 {
		return nil, "", errors.New("empty body")
	}
	if int64(len(body)) > c.maxBytes {
		return nil, "", errors.New("artifact exceeds store byte budget")
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	ext := ".pcap"
	switch mime {
	case "application/zip":
		ext = ".zip"
	case "application/json":
		ext = ".json"
	case "application/octet-stream":
		ext = ".bin"
	case "text/plain":
		ext = ".txt"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked()
	var used int64
	for _, e := range c.entries {
		used += e.SizeBytes
	}
	for len(c.entries) >= c.maxEntries || int64(len(body)) > c.maxBytes-used {
		old := c.entries[0]
		used -= old.SizeBytes
		c.removeFile(old)
		c.entries[0] = nil
		c.entries = c.entries[1:]
	}
	owned := make([]byte, len(body))
	copy(owned, body)
	filename := fmt.Sprintf("%s-%s%s", kind, id, ext)
	path := filepath.Join(c.dir, filename)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		// Fall back to memory-only if disk write fails.
		path = ""
	}
	entry := &carveEntry{
		ID:        id,
		Path:      path,
		Bytes:     owned,
		SizeBytes: int64(len(body)),
		SHA256:    hex.EncodeToString(sum[:]),
		Kind:      kind,
		Source:    source,
		SessionID: sessionID,
		CreatedAt: time.Now(),
		MIMEType:  mime,
	}
	c.entries = append(c.entries, entry)
	receipt := *entry
	receipt.Bytes = nil
	return &receipt, "netcap://carve/" + id, nil
}

// Get returns the entry for id, or nil if not found / evicted.
func (c *CarveStore) Get(id string) *carveEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked()
	for _, e := range c.entries {
		if e.ID == id {
			copy := *e
			copy.Bytes = append([]byte{}, e.Bytes...)
			return &copy
		}
	}
	return nil
}

// page copies only the authorized range while the entry is retained.
func (c *CarveStore) page(id, session string, offset, limit int) (*carveEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked()
	for _, e := range c.entries {
		if e.ID != id {
			continue
		}
		if e.SessionID != "" && session != e.SessionID {
			return nil, errors.New("original session_id required")
		}
		if offset < 0 || offset > len(e.Bytes) || limit < 1 || limit > 65536 {
			return nil, errors.New("invalid artifact page bounds")
		}
		page := *e
		n := min(limit, len(e.Bytes)-offset)
		page.Bytes = append([]byte(nil), e.Bytes[offset:offset+n]...)
		return &page, nil
	}
	return nil, errors.New("artifact unavailable or expired")
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

func (c *CarveStore) DeleteSessions(ids ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.entries[:0]
	for _, entry := range c.entries {
		remove := false
		for _, id := range ids {
			if id != "" && entry.SessionID == id {
				remove = true
			}
		}
		if remove {
			c.removeFile(entry)
		} else {
			kept = append(kept, entry)
		}
	}
	c.entries = kept
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
