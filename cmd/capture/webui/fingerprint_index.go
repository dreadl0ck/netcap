package webui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"
)

const (
	fingerprintCacheSize  = 3
	fingerprintCacheBytes = 64 << 20
	fingerprintMaxRows    = 20_000
	fingerprintMaxIDs     = 4096
)

var fingerprintSources = [...]string{
	"SSH", "TLSClientHello", "TLSServerHello", "Host", "DHCPv4", "HTTP", "TLSCertificate", "TCP",
}

type fingerprintSnapshot struct {
	rows  []FingerprintSummary
	stats FingerprintsStats
	byID  map[string]*roaring.Bitmap
	bytes uint64
}

func newFingerprintSnapshot(rows []FingerprintSummary) *fingerprintSnapshot {
	s := &fingerprintSnapshot{rows: rows, stats: computeFingerprintStats(rows)}
	if len(rows) <= fingerprintMaxRows {
		s.byID = make(map[string]*roaring.Bitmap)
	}
	for i, row := range rows {
		s.bytes += uint64(128 + len(row.Fingerprint) + len(row.Type) + len(row.Description))
		for _, host := range row.Hosts {
			s.bytes += uint64(16 + len(host))
		}
		for _, id := range row.CommunityIDs {
			s.bytes += uint64(16 + len(id))
			if s.byID == nil || id == "" {
				continue
			}
			bitmap := s.byID[id]
			if bitmap == nil {
				if len(s.byID) >= fingerprintMaxIDs {
					s.byID = nil
					continue
				}
				bitmap = roaring.New()
				s.byID[id] = bitmap
			}
			bitmap.Add(uint32(i))
		}
	}
	for id, bitmap := range s.byID {
		s.bytes += uint64(128+len(id)) + bitmap.GetSizeInBytes()
	}
	return s
}

func (s *fingerprintSnapshot) filter(opts fingerprintListOptions) []FingerprintSummary {
	if len(opts.communityIDFilter) == 0 || s.byID == nil {
		return filterFingerprints(s.rows, opts)
	}
	var matches *roaring.Bitmap
	for id := range opts.communityIDFilter {
		if bitmap := s.byID[id]; bitmap != nil {
			if matches == nil {
				matches = bitmap.Clone()
			} else {
				matches.Or(bitmap)
			}
		}
	}
	if matches == nil {
		return []FingerprintSummary{}
	}
	terms := parseSearchQuery(opts.search)
	filtered := make([]FingerprintSummary, 0, matches.GetCardinality())
	iter := matches.Iterator()
	for iter.HasNext() {
		row := s.rows[iter.Next()]
		if opts.typeFilter != "" && row.Type != opts.typeFilter {
			continue
		}
		if len(terms) > 0 && !fingerprintMatchesSearch(row, terms) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func (s *fingerprintSnapshot) count(ids map[string]bool) int64 {
	if s.byID != nil {
		var matches *roaring.Bitmap
		for id := range ids {
			if bitmap := s.byID[id]; bitmap != nil {
				if matches == nil {
					matches = bitmap.Clone()
				} else {
					matches.Or(bitmap)
				}
			}
		}
		if matches != nil {
			return int64(matches.GetCardinality())
		}
		return 0
	}
	var count int64
	for _, row := range s.rows {
		if containsAnyCommunityIDBool(row.CommunityIDs, ids) {
			count++
		}
	}
	return count
}

func containsAnyCommunityIDBool(values []string, selected map[string]bool) bool {
	for _, id := range values {
		if selected[id] {
			return true
		}
	}
	return false
}

type fingerprintCacheEntry struct {
	generation fingerprintAuditGeneration
	used       time.Time
	ready      chan struct{}
	snapshot   *fingerprintSnapshot
	err        error
}

var (
	fingerprintBuildSlots      = make(chan struct{}, 2)
	errFingerprintBuildBusy    = errors.New("fingerprint inventory builds are busy")
	errFingerprintAuditChanged = errors.New("fingerprint audits changed during inventory build; retry")
)

var fingerprintCache = struct {
	sync.Mutex
	entries map[string]*fingerprintCacheEntry
	bytes   uint64
}{entries: make(map[string]*fingerprintCacheEntry)}

type fingerprintAuditGeneration [len(fingerprintSources)]os.FileInfo

func fingerprintGeneration(outDir string) (fingerprintAuditGeneration, error) {
	var generation fingerprintAuditGeneration
	for i, name := range fingerprintSources {
		path := filepath.Join(outDir, name+".ncap.gz")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return generation, err
		}
		generation[i] = info
	}
	return generation, nil
}

func (g fingerprintAuditGeneration) same(other fingerprintAuditGeneration) bool {
	for i, info := range g {
		if !sameConnectionGeneration(info, other[i]) {
			return false
		}
	}
	return true
}

func fingerprintSnapshotFor(outDir string) (*fingerprintSnapshot, error) {
	for attempt := 0; attempt < 2; attempt++ {
		generation, err := fingerprintGeneration(outDir)
		if err != nil {
			return nil, err
		}
		fingerprintCache.Lock()
		entry := fingerprintCache.entries[outDir]
		if entry == nil || !entry.generation.same(generation) {
			select {
			case fingerprintBuildSlots <- struct{}{}:
			default:
				fingerprintCache.Unlock()
				return nil, errFingerprintBuildBusy
			}
			if entry != nil {
				select {
				case <-entry.ready:
					if entry.snapshot != nil {
						fingerprintCache.bytes -= entry.snapshot.bytes
					}
				default:
				}
			}
			entry = &fingerprintCacheEntry{generation: generation, ready: make(chan struct{})}
			fingerprintCache.entries[outDir] = entry
			fingerprintCache.Unlock()

			snapshot, buildErr := buildFingerprintSnapshot(outDir, generation)
			fingerprintCache.Lock()
			entry.snapshot, entry.err = snapshot, buildErr
			close(entry.ready)
			if fingerprintCache.entries[outDir] == entry {
				if buildErr != nil || entry.snapshot.bytes > fingerprintCacheBytes {
					delete(fingerprintCache.entries, outDir)
				} else {
					entry.used = time.Now()
					fingerprintCache.bytes += entry.snapshot.bytes
					fingerprintCacheEvictLocked()
				}
			}
			fingerprintCache.Unlock()
		} else {
			entry.used = time.Now()
			fingerprintCache.Unlock()
			<-entry.ready
		}
		if errors.Is(entry.err, errFingerprintAuditChanged) {
			continue
		}
		if entry.err != nil {
			return nil, entry.err
		}
		after, err := fingerprintGeneration(outDir)
		if err != nil {
			return nil, err
		}
		if generation.same(after) {
			return entry.snapshot, nil
		}
	}
	return nil, errFingerprintAuditChanged
}

func buildFingerprintSnapshot(outDir string, generation fingerprintAuditGeneration) (*fingerprintSnapshot, error) {
	defer func() { <-fingerprintBuildSlots }()
	rows, err := readFingerprintGeneration(outDir, generation)
	if err != nil {
		return nil, err
	}
	return newFingerprintSnapshot(rows), nil
}

func readFingerprintGeneration(outDir string, generation fingerprintAuditGeneration) ([]FingerprintSummary, error) {
	budget := newFingerprintAuditBudget(context.Background())
	budget.verifySource = func(path string, info os.FileInfo) error {
		for i, name := range fingerprintSources {
			if filepath.Base(path) == name+".ncap.gz" && sameConnectionGeneration(generation[i], info) {
				return nil
			}
		}
		return errFingerprintAuditChanged
	}
	return readFingerprintInventory(outDir, &budget)
}

func cachedFingerprintRows(outDir string) []FingerprintSummary {
	snapshot, err := fingerprintSnapshotFor(outDir)
	if err != nil {
		return nil
	}
	return snapshot.rows
}

func fingerprintCacheEvictLocked() {
	for len(fingerprintCache.entries) > fingerprintCacheSize || fingerprintCache.bytes > fingerprintCacheBytes {
		var oldestKey string
		var oldest time.Time
		for key, entry := range fingerprintCache.entries {
			select {
			case <-entry.ready:
				if oldestKey == "" || entry.used.Before(oldest) {
					oldestKey, oldest = key, entry.used
				}
			default:
			}
		}
		if oldestKey == "" {
			return
		}
		fingerprintCache.bytes -= fingerprintCache.entries[oldestKey].snapshot.bytes
		delete(fingerprintCache.entries, oldestKey)
	}
}
