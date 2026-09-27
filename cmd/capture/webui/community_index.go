package webui

import (
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
)

const (
	communityIndexCacheSize  = 64
	communityIndexCacheBytes = 64 << 20
	communityIndexMaxRecords = 1_000_000
	communityIndexMaxIDs     = 4096
)

type communityFileIndex struct {
	total int64
	byID  map[string]*roaring.Bitmap
	bytes uint64
}

func (idx *communityFileIndex) count(ids map[string]bool) int64 {
	if len(ids) == 1 {
		for id := range ids {
			if bitmap := idx.byID[id]; bitmap != nil {
				return int64(bitmap.GetCardinality())
			}
		}
		return 0
	}

	var selected *roaring.Bitmap
	for id := range ids {
		if bitmap := idx.byID[id]; bitmap != nil {
			if selected == nil {
				selected = bitmap.Clone()
			} else {
				selected.Or(bitmap)
			}
		}
	}
	if selected == nil {
		return 0
	}
	return int64(selected.GetCardinality())
}

type communityIndexEntry struct {
	size  int64
	mtime time.Time
	used  time.Time
	ready chan struct{}
	index *communityFileIndex
}

var communityIndexCache = struct {
	sync.Mutex
	files map[string]*communityIndexEntry
	bytes uint64
}{files: make(map[string]*communityIndexEntry)}

// communityCounts uses an exact, per-file ordinal index. Oversized or changing
// files are counted by streaming instead of publishing a partial index.
func communityCounts(path string, ids map[string]bool) (int64, int64, error) {
	for attempt := 0; attempt < 2; attempt++ {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		if err != nil {
			return 0, 0, err
		}

		communityIndexCache.Lock()
		entry := communityIndexCache.files[path]
		if entry == nil || entry.size != info.Size() || !entry.mtime.Equal(info.ModTime()) {
			if entry != nil {
				select {
				case <-entry.ready:
					if entry.index != nil {
						communityIndexCache.bytes -= entry.index.bytes
					}
				default:
				}
			}
			entry = &communityIndexEntry{size: info.Size(), mtime: info.ModTime(), ready: make(chan struct{})}
			communityIndexCache.files[path] = entry
			communityIndexCache.Unlock()

			idx, buildErr := buildCommunityIndex(path)
			communityIndexCache.Lock()
			entry.index = idx
			close(entry.ready)
			if buildErr != nil {
				if communityIndexCache.files[path] == entry {
					delete(communityIndexCache.files, path)
				}
			} else if communityIndexCache.files[path] == entry {
				entry.used = time.Now()
				if idx != nil {
					communityIndexCache.bytes += idx.bytes
				}
				communityIndexEvictLocked()
			}
			communityIndexCache.Unlock()
			if buildErr != nil {
				return 0, 0, buildErr
			}
		} else {
			entry.used = time.Now()
			communityIndexCache.Unlock()
			<-entry.ready
		}

		after, err := os.Stat(path)
		if err == nil && after.Size() == info.Size() && after.ModTime().Equal(info.ModTime()) {
			if entry.index != nil {
				return entry.index.total, entry.index.count(ids), nil
			}
			break
		}
	}
	return scanCommunityCounts(path, ids)
}

func communityIndexEvictLocked() {
	for len(communityIndexCache.files) > communityIndexCacheSize || communityIndexCache.bytes > communityIndexCacheBytes {
		var oldestPath string
		var oldest time.Time
		for path, entry := range communityIndexCache.files {
			select {
			case <-entry.ready:
				if oldestPath == "" || entry.used.Before(oldest) {
					oldestPath, oldest = path, entry.used
				}
			default:
			}
		}
		if oldestPath == "" {
			return
		}
		if idx := communityIndexCache.files[oldestPath].index; idx != nil {
			communityIndexCache.bytes -= idx.bytes
		}
		delete(communityIndexCache.files, oldestPath)
	}
}

var errCommunityIndexTooLarge = errors.New("community index size limit exceeded")

func buildCommunityIndex(path string) (*communityFileIndex, error) {
	idx := &communityFileIndex{byID: make(map[string]*roaring.Bitmap)}
	err := walkCommunityRecords(path, func(id string) error {
		if idx.total >= communityIndexMaxRecords {
			return errCommunityIndexTooLarge
		}
		if id != "" {
			bitmap := idx.byID[id]
			if bitmap == nil {
				if len(idx.byID) >= communityIndexMaxIDs {
					return errCommunityIndexTooLarge
				}
				bitmap = roaring.New()
				idx.byID[id] = bitmap
			}
			bitmap.Add(uint32(idx.total))
		}
		idx.total++
		return nil
	})
	if errors.Is(err, errCommunityIndexTooLarge) {
		return nil, nil
	}
	if err == nil {
		for id, bitmap := range idx.byID {
			idx.bytes += uint64(len(id)) + 128 + bitmap.GetSizeInBytes()
		}
	}
	return idx, err
}

func scanCommunityCounts(path string, ids map[string]bool) (int64, int64, error) {
	var total, matched int64
	err := walkCommunityRecords(path, func(id string) error {
		total++
		if id != "" && ids[id] {
			matched++
		}
		return nil
	})
	return total, matched, err
}

func walkCommunityRecords(path string, visit func(string) error) error {
	reader, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		return err
	}
	defer reader.Close()

	header, err := reader.ReadHeader()
	if err != nil {
		return err
	}
	record := netio.InitRecord(header.Type)
	if record == nil {
		return errors.New("unsupported audit record type")
	}

	field, hasID := reflect.TypeOf(record).Elem().FieldByName("CommunityID")
	hasID = hasID && field.Type.Kind() == reflect.String
	for {
		if err := reader.Next(record); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		id := ""
		if hasID {
			id = reflect.ValueOf(record).Elem().FieldByIndex(field.Index).String()
		}
		if err := visit(id); err != nil {
			return err
		}
	}
}
