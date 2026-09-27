package webui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"
)

const (
	certificateCacheSize  = 3
	certificateCacheBytes = 64 << 20
	certificateMaxRows    = 20_000
	certificateMaxIDs     = 4096
)

type certificateSnapshot struct {
	rows  []CertificateSummary
	byID  map[string]*roaring.Bitmap
	bytes uint64
}

func newCertificateSnapshot(rows []CertificateSummary) *certificateSnapshot {
	s := &certificateSnapshot{rows: rows}
	if len(rows) <= certificateMaxRows {
		s.byID = make(map[string]*roaring.Bitmap)
	}
	for i, row := range rows {
		s.bytes += uint64(256 + len(row.SHA256Fingerprint) + len(row.SubjectCommonName) + len(row.IssuerCommonName))
		for _, id := range row.CommunityIDs {
			s.bytes += uint64(len(id) + 16)
			if s.byID == nil {
				continue
			}
			bitmap := s.byID[id]
			if bitmap == nil {
				if len(s.byID) >= certificateMaxIDs {
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

func (s *certificateSnapshot) count(ids map[string]bool) int64 {
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
		if matches == nil {
			return 0
		}
		return int64(matches.GetCardinality())
	}
	var count int64
	for _, row := range s.rows {
		if containsAnyCommunityIDBool(row.CommunityIDs, ids) {
			count++
		}
	}
	return count
}

type certificateCacheEntry struct {
	generation string
	used       time.Time
	ready      chan struct{}
	snapshot   *certificateSnapshot
}

var certificateCache = struct {
	sync.Mutex
	entries map[string]*certificateCacheEntry
	bytes   uint64
}{entries: make(map[string]*certificateCacheEntry)}

func certificateGeneration(outDir string) (string, error) {
	info, err := os.Stat(filepath.Join(outDir, "TLSCertificate.ncap.gz"))
	if errors.Is(err, os.ErrNotExist) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}

func certificateSnapshotFor(outDir string) (*certificateSnapshot, error) {
	for attempt := 0; attempt < 2; attempt++ {
		generation, err := certificateGeneration(outDir)
		if err != nil {
			return nil, err
		}
		certificateCache.Lock()
		entry := certificateCache.entries[outDir]
		if entry == nil || entry.generation != generation {
			if entry != nil {
				select {
				case <-entry.ready:
					if entry.snapshot != nil {
						certificateCache.bytes -= entry.snapshot.bytes
					}
				default:
				}
			}
			entry = &certificateCacheEntry{generation: generation, ready: make(chan struct{})}
			certificateCache.entries[outDir] = entry
			certificateCache.Unlock()

			rows, buildErr := readCertificates(outDir)
			certificateCache.Lock()
			if buildErr == nil {
				entry.snapshot = newCertificateSnapshot(rows)
			}
			close(entry.ready)
			if certificateCache.entries[outDir] == entry {
				if buildErr != nil || entry.snapshot.bytes > certificateCacheBytes {
					delete(certificateCache.entries, outDir)
				} else {
					entry.used = time.Now()
					certificateCache.bytes += entry.snapshot.bytes
					certificateEvictLocked()
				}
			}
			certificateCache.Unlock()
			if buildErr != nil {
				return nil, buildErr
			}
		} else {
			entry.used = time.Now()
			certificateCache.Unlock()
			<-entry.ready
			if entry.snapshot == nil {
				continue
			}
		}
		after, err := certificateGeneration(outDir)
		if err != nil {
			return nil, err
		}
		if after == generation {
			return entry.snapshot, nil
		}
	}
	rows, err := readCertificates(outDir)
	if err != nil {
		return nil, err
	}
	return newCertificateSnapshot(rows), nil
}

func cachedCertificateRows(outDir string) []CertificateSummary {
	snapshot, err := certificateSnapshotFor(outDir)
	if err != nil {
		return nil
	}
	return snapshot.rows
}

func certificateEvictLocked() {
	for len(certificateCache.entries) > certificateCacheSize || certificateCache.bytes > certificateCacheBytes {
		var oldestKey string
		var oldest time.Time
		for key, entry := range certificateCache.entries {
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
		certificateCache.bytes -= certificateCache.entries[oldestKey].snapshot.bytes
		delete(certificateCache.entries, oldestKey)
	}
}
