package webui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

const (
	communityIndexCacheSize      = 64
	communityIndexCacheBytes     = 64 << 20
	communityIndexMaxRecords     = 1_000_000
	communityIndexMaxIDs         = 4096
	communityIndexMaxKeyBytes    = 4 << 20
	communityIndexMaxMemberships = 1_000_000
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
	info  os.FileInfo
	used  time.Time
	ready chan struct{}
	index *communityFileIndex
}

var communityIndexCache = struct {
	sync.Mutex
	files map[string]*communityIndexEntry
	bytes uint64
}{files: make(map[string]*communityIndexEntry)}

// communityCachedTotal reuses a completed bitmap generation without building
// one just to answer an unfiltered count.
func communityCachedTotal(path string) (int64, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	communityIndexCache.Lock()
	entry := communityIndexCache.files[path]
	if entry == nil || !entry.matches(info) {
		communityIndexCache.Unlock()
		return 0, false
	}
	select {
	case <-entry.ready:
		if entry.index != nil {
			entry.used = time.Now()
			count := entry.index.total
			communityIndexCache.Unlock()
			return count, true
		}
	default:
	}
	communityIndexCache.Unlock()
	return 0, false
}

func (e *communityIndexEntry) matches(info os.FileInfo) bool {
	return sameCommunityAudit(e.info, info)
}

func sameCommunityAudit(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// communityIndexFor publishes only complete generations. Oversized or changing
// files retain the streaming fallback without publishing a partial index.
func communityIndexFor(path string) (*communityFileIndex, error) {
	return communityIndexForContext(context.Background(), path)
}

func communityIndexForContext(ctx context.Context, path string) (*communityFileIndex, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, artifactio.ErrPath
		}

		communityIndexCache.Lock()
		entry := communityIndexCache.files[path]
		if entry == nil || !entry.matches(info) {
			if entry != nil {
				select {
				case <-entry.ready:
					if entry.index != nil {
						communityIndexCache.bytes -= entry.index.bytes
					}
				default:
				}
			}
			entry = &communityIndexEntry{info: info, ready: make(chan struct{})}
			communityIndexCache.files[path] = entry
			communityIndexCache.Unlock()

			idx, buildErr := buildCommunityIndexContext(ctx, path, info)
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
				return nil, buildErr
			}
		} else {
			entry.used = time.Now()
			communityIndexCache.Unlock()
			select {
			case <-entry.ready:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		after, err := os.Lstat(path)
		if err == nil && entry.matches(after) {
			return entry.index, nil
		}
	}
	return nil, nil
}

func communityCounts(path string, ids map[string]bool) (int64, int64, error) {
	return communityCountsContext(context.Background(), path, ids)
}

func communityCountsContext(ctx context.Context, path string, ids map[string]bool) (int64, int64, error) {
	idx, err := communityIndexForContext(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	if idx != nil {
		return idx.total, idx.count(ids), nil
	}
	total, matched, err := scanCommunityCountsContext(ctx, path, ids)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	return total, matched, err
}

func communitySelectedBitmap(ctx context.Context, path string, ids map[string]bool) (*roaring.Bitmap, int64, error) {
	idx, err := communityIndexForContext(ctx, path)
	if err != nil || idx == nil {
		return nil, 0, err
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
		selected = roaring.New()
	}
	return selected, idx.total, nil
}

func auditRecordMatchesCommunityID(record any, selected map[string]bool) bool {
	if single, ok := record.(interface{ GetCommunityID() string }); ok {
		if id := single.GetCommunityID(); id != "" && selected[id] {
			return true
		}
	}
	if multiple, ok := record.(interface{ GetCommunityIDs() []string }); ok {
		for _, id := range multiple.GetCommunityIDs() {
			if id != "" && selected[id] {
				return true
			}
		}
	}
	return false
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

func buildCommunityIndex(path string, expected os.FileInfo) (*communityFileIndex, error) {
	return buildCommunityIndexContext(context.Background(), path, expected)
}

func buildCommunityIndexContext(ctx context.Context, path string, expected os.FileInfo) (*communityFileIndex, error) {
	idx := &communityFileIndex{byID: make(map[string]*roaring.Bitmap)}
	keyBytes := 0
	memberships := 0
	err := walkCommunityRecords(ctx, path, expected, func(id string, ids []string) error {
		if idx.total >= communityIndexMaxRecords {
			return errCommunityIndexTooLarge
		}
		add := func(id string) error {
			if id == "" {
				return nil
			}
			bitmap := idx.byID[id]
			ordinal := uint32(idx.total)
			if memberships == communityIndexMaxMemberships {
				if bitmap != nil && bitmap.Contains(ordinal) {
					return nil
				}
				return errCommunityIndexTooLarge
			}
			if bitmap == nil {
				if len(idx.byID) >= communityIndexMaxIDs || len(id) > communityIndexMaxKeyBytes-keyBytes {
					return errCommunityIndexTooLarge
				}
				keyBytes += len(id)
				bitmap = roaring.New()
				idx.byID[id] = bitmap
			}
			if bitmap.CheckedAdd(ordinal) {
				memberships++
			}
			return nil
		}
		if err := add(id); err != nil {
			return err
		}
		for _, id := range ids {
			if err := add(id); err != nil {
				return err
			}
		}
		idx.total++
		return nil
	})
	if errors.Is(err, errCommunityIndexTooLarge) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for id, bitmap := range idx.byID {
		idx.bytes += uint64(len(id)) + 128 + bitmap.GetSizeInBytes()
	}
	return idx, nil
}

func scanCommunityCounts(path string, selected map[string]bool) (int64, int64, error) {
	return scanCommunityCountsContext(context.Background(), path, selected)
}

func scanCommunityCountsContext(ctx context.Context, path string, selected map[string]bool) (int64, int64, error) {
	var total, matched int64
	err := walkCommunityRecords(ctx, path, nil, func(id string, ids []string) error {
		total++
		if id != "" && selected[id] {
			matched++
			return nil
		}
		for _, candidate := range ids {
			if candidate != "" && selected[candidate] {
				matched++
				break
			}
		}
		return nil
	})
	return total, matched, err
}

var errCommunityAuditChanged = errors.New("audit file changed during Community ID scan")

func walkCommunityRecords(ctx context.Context, path string, expected os.FileInfo, visit func(string, []string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, opened, err := artifactio.Open(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return err
	}
	if expected != nil && !sameCommunityAudit(expected, opened) {
		f.Close()
		return errCommunityAuditChanged
	}
	reader, err := auditRecordReaderFromInput(f, f, strings.HasSuffix(path, ".gz"), func(input io.Reader) io.Reader {
		return auditContextReader{ctx: ctx, input: input}
	})
	if err != nil {
		return err
	}
	defer reader.Close()

	header, err := reader.ReadHeader()
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".gz"), defaults.FileExtension)
	if want, ok := types.Type_value["NC_"+name]; ok && header.Type != types.Type(want) {
		return errors.New("audit header type does not match file name")
	}
	record := netio.InitRecord(header.Type)
	if record == nil {
		return errors.New("unsupported audit record type")
	}

	field, hasID := reflect.TypeOf(record).Elem().FieldByName("CommunityID")
	hasID = hasID && field.Type.Kind() == reflect.String
	listField, hasIDs := reflect.TypeOf(record).Elem().FieldByName("CommunityIDs")
	hasIDs = hasIDs && listField.Type == reflect.TypeFor[[]string]()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := reader.delimitedReader.NextProto(record); err != nil {
			if errors.Is(err, io.EOF) {
				after, err := f.Stat()
				if err != nil {
					return err
				}
				if !sameCommunityAudit(opened, after) {
					return errCommunityAuditChanged
				}
				return nil
			}
			return err
		}
		id := ""
		if hasID {
			id = reflect.ValueOf(record).Elem().FieldByIndex(field.Index).String()
		}
		var ids []string
		if hasIDs {
			ids = reflect.ValueOf(record).Elem().FieldByIndex(listField.Index).Interface().([]string)
		}
		if err := visit(id, ids); err != nil {
			return err
		}
	}
}
