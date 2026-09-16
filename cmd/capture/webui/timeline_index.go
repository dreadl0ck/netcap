/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// Timeline index sizing. The index keeps one entry per audit record in memory
// (24 bytes plus interned endpoint strings), so the caps below bound the worst
// case footprint for very large captures.
const (
	timelineMaxEventsPerType = 2_000_000
	timelineMaxEventsTotal   = 5_000_000
	timelineCacheSize        = 3
)

// Index build states reported to the frontend.
const (
	timelineStateIndexing = "indexing"
	timelineStateReady    = "ready"
	timelineStateError    = "error"
)

// tlEvent is a single indexed audit record occurrence. Src and Dst are indices
// into the owning type index string table so repeated endpoints cost 4 bytes.
type tlEvent struct {
	Time    int64
	Ordinal int32
	Src     int32
	Dst     int32
}

// tlTypeIndex holds the time index for one audit record type (one timeline track).
type tlTypeIndex struct {
	Name      string
	Layer     string
	LayerRank int

	// Events is sorted by (Time, Ordinal).
	Events []tlEvent
	// Ends is parallel to Events and only set for record types that carry a
	// validated end timestamp (TimestampFirst/TimestampLast). Nil otherwise.
	Ends        []int64
	MaxDuration int64

	Total     int64 // records present in the file
	Invalid   int64 // records without a usable timestamp
	Truncated bool  // index does not cover every record of this type

	MinTime int64
	MaxTime int64

	strings []string
}

func (t *tlTypeIndex) str(i int32) string {
	if i < 0 || int(i) >= len(t.strings) {
		return ""
	}

	return t.strings[i]
}

// hasDuration reports whether this type renders as a bar rather than a point.
func (t *tlTypeIndex) hasDuration() bool { return t.Ends != nil }

// timelineIndex is the complete time index for one output directory.
type timelineIndex struct {
	Generation string
	Types      []*tlTypeIndex
	byName     map[string]*tlTypeIndex

	MinTime      int64
	MaxTime      int64
	CaptureMin   int64
	CaptureMax   int64
	TotalRecords int64
	TotalEvents  int64
	Truncated    bool
}

func (idx *timelineIndex) typeIndex(name string) *tlTypeIndex {
	if idx == nil {
		return nil
	}

	return idx.byName[name]
}

// timelineIndexEntry is a cache slot for one output directory.
type timelineIndexEntry struct {
	fingerprint string // immutable after creation

	mu     sync.RWMutex
	state  string
	errMsg string
	done   int64
	total  int64
	index  *timelineIndex

	lastUsed time.Time // guarded by timelineCache
}

// timelineIndexStatus is the snapshot handed to request handlers.
type timelineIndexStatus struct {
	State string
	Err   string
	Done  int64
	Total int64
	Index *timelineIndex
}

var timelineCache = struct {
	sync.Mutex
	entries map[string]*timelineIndexEntry
}{entries: make(map[string]*timelineIndexEntry)}

// Building an index can consume the full event budget, so only one generation
// is built at a time across all capture sessions. The cache bounds queued work.
var timelineBuildSlot = make(chan struct{}, 1)

// timelineFileRef points at one audit record file to index.
type timelineFileRef struct {
	path string
	name string // audit record type name
}

// timelineFingerprint identifies the current generation of audit records in
// outDir. Any change in the set of files, their size or mtime invalidates the
// cached index.
func timelineFingerprint(outDir string) (string, []timelineFileRef, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "empty", nil, nil
		}

		return "", nil, err
	}

	compressedSuffix := defaults.FileExtension + ".gz"
	filesByType := make(map[string]timelineFileRef, len(entries))
	h := sha256.New()

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), compressedSuffix) && !strings.HasSuffix(e.Name(), defaults.FileExtension)) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		info, statErr := os.Stat(filepath.Join(outDir, name))
		if statErr != nil {
			continue
		}
		if info.Size() == 0 {
			continue
		}

		fmt.Fprintf(h, "%s:%d:%d\n", name, info.Size(), info.ModTime().UnixNano())

		typeName := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), defaults.FileExtension)
		candidate := timelineFileRef{
			path: filepath.Join(outDir, name),
			name: typeName,
		}
		current, exists := filesByType[typeName]
		if !exists || (!strings.HasSuffix(current.path, ".gz") && strings.HasSuffix(candidate.path, ".gz")) {
			filesByType[typeName] = candidate
		}
	}

	files := make([]timelineFileRef, 0, len(filesByType))
	for _, file := range filesByType {
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	if len(files) == 0 {
		return "empty", nil, nil
	}

	return hex.EncodeToString(h.Sum(nil))[:16], files, nil
}

// timelineIndexFor returns the index for outDir, kicking off a background build
// when no current index exists.
func timelineIndexFor(outDir string) timelineIndexStatus {
	fingerprint, files, err := timelineFingerprint(outDir)
	if err != nil {
		return timelineIndexStatus{State: timelineStateError, Err: err.Error()}
	}

	if len(files) == 0 {
		return timelineIndexStatus{
			State: timelineStateReady,
			Index: &timelineIndex{Generation: fingerprint, byName: map[string]*tlTypeIndex{}},
		}
	}

	timelineCache.Lock()

	entry := timelineCache.entries[outDir]
	// Never overlap builds for the same output directory. Files in a live
	// capture can change on every metadata poll; the completed generation will
	// be replaced on the next request if its fingerprint is already stale.
	entryIndexing := false
	if entry != nil {
		entry.mu.RLock()
		entryIndexing = entry.state == timelineStateIndexing
		entry.mu.RUnlock()
	}

	if entry == nil || (entry.fingerprint != fingerprint && !entryIndexing) {
		if entry == nil && len(timelineCache.entries) >= timelineCacheSize {
			var oldestKey string
			var oldest time.Time
			for key, candidate := range timelineCache.entries {
				candidate.mu.RLock()
				ready := candidate.state != timelineStateIndexing
				candidate.mu.RUnlock()
				if ready && (oldestKey == "" || candidate.lastUsed.Before(oldest)) {
					oldestKey, oldest = key, candidate.lastUsed
				}
			}
			if oldestKey == "" {
				timelineCache.Unlock()

				return timelineIndexStatus{State: timelineStateError, Err: "timeline indexer is busy"}
			}
			delete(timelineCache.entries, oldestKey)
		}

		entry = &timelineIndexEntry{
			fingerprint: fingerprint,
			state:       timelineStateIndexing,
			total:       int64(len(files)),
		}
		timelineCache.entries[outDir] = entry
		timelineEvictLocked()

		go buildTimelineIndex(entry, fingerprint, files)
	}

	entry.lastUsed = time.Now()
	timelineCache.Unlock()

	entry.mu.RLock()
	defer entry.mu.RUnlock()

	return timelineIndexStatus{
		State: entry.state,
		Err:   entry.errMsg,
		Done:  entry.done,
		Total: entry.total,
		Index: entry.index,
	}
}

// timelineEvictLocked drops the least recently used ready entries. Must be
// called while holding timelineCache.
func timelineEvictLocked() {
	for len(timelineCache.entries) > timelineCacheSize {
		var (
			oldestKey string
			oldest    time.Time
		)

		for key, e := range timelineCache.entries {
			e.mu.RLock()
			indexing := e.state == timelineStateIndexing
			e.mu.RUnlock()

			if indexing {
				continue
			}

			if oldestKey == "" || e.lastUsed.Before(oldest) {
				oldestKey, oldest = key, e.lastUsed
			}
		}

		if oldestKey == "" {
			return
		}

		delete(timelineCache.entries, oldestKey)
	}
}

// buildTimelineIndex indexes every audit record file of one generation.
func buildTimelineIndex(entry *timelineIndexEntry, fingerprint string, files []timelineFileRef) {
	timelineBuildSlot <- struct{}{}
	defer func() { <-timelineBuildSlot }()

	defer func() {
		if r := recover(); r != nil {
			entry.mu.Lock()
			entry.state = timelineStateError
			entry.errMsg = fmt.Sprintf("timeline indexing failed: %v", r)
			entry.mu.Unlock()
		}
	}()

	workers := runtime.NumCPU()
	if workers > 4 {
		workers = 4
	}
	if workers > len(files) {
		workers = len(files)
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]*tlTypeIndex, 0, len(files))
		next    int64
		done    int64
		failed  atomic.Bool
	)

	// Divide the global budget across tracks before reading. This bounds peak
	// memory during parallel indexing rather than trimming only after every
	// track has already allocated its maximum.
	perTypeLimit := timelineMaxEventsTotal / len(files)
	if perTypeLimit > timelineMaxEventsPerType {
		perTypeLimit = timelineMaxEventsPerType
	}
	if perTypeLimit < 1 {
		perTypeLimit = 1
	}

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				i := int(atomic.AddInt64(&next, 1)) - 1
				if i >= len(files) {
					return
				}

				ti, err := indexTimelineType(files[i].path, files[i].name, perTypeLimit)

				atomic.AddInt64(&done, 1)

				entry.mu.Lock()
				entry.done = atomic.LoadInt64(&done)
				entry.mu.Unlock()

				if err != nil || ti == nil || len(ti.Events) == 0 {
					if err != nil {
						failed.Store(true)
					}
					continue
				}

				mu.Lock()
				results = append(results, ti)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	idx := assembleTimelineIndex(fingerprint, results)
	if failed.Load() {
		idx.Truncated = true
	}

	entry.mu.Lock()
	entry.index = idx
	entry.state = timelineStateReady
	entry.done = entry.total
	entry.mu.Unlock()

	timelineCache.Lock()
	timelineEvictLocked()
	timelineCache.Unlock()
}

// assembleTimelineIndex orders the tracks, applies the global event budget and
// computes the capture bounds.
func assembleTimelineIndex(fingerprint string, types []*tlTypeIndex) *timelineIndex {
	sort.Slice(types, func(i, j int) bool {
		if types[i].LayerRank != types[j].LayerRank {
			return types[i].LayerRank < types[j].LayerRank
		}

		return types[i].Name < types[j].Name
	})

	idx := &timelineIndex{
		Generation: fingerprint,
		Types:      types,
		byName:     make(map[string]*tlTypeIndex, len(types)),
		MinTime:    math.MaxInt64,
		CaptureMin: math.MaxInt64,
	}

	var total int64
	for _, t := range types {
		total += int64(len(t.Events))
	}

	// Enforce the global budget by trimming the largest tracks first.
	if total > timelineMaxEventsTotal {
		bySize := make([]*tlTypeIndex, len(types))
		copy(bySize, types)
		sort.Slice(bySize, func(i, j int) bool { return len(bySize[i].Events) > len(bySize[j].Events) })

		for _, t := range bySize {
			if total <= timelineMaxEventsTotal {
				break
			}

			excess := total - timelineMaxEventsTotal
			keep := int64(len(t.Events)) - excess
			if keep < 0 {
				keep = 0
			}

			total -= int64(len(t.Events)) - keep
			t.Events = t.Events[:keep]
			if t.Ends != nil {
				t.Ends = t.Ends[:keep]
			}
			t.Truncated = true
			idx.Truncated = true
		}
	}

	for _, t := range types {
		if len(t.Events) == 0 {
			continue
		}

		t.MinTime = t.Events[0].Time
		t.MaxTime = t.Events[len(t.Events)-1].Time
		if t.Ends != nil {
			for _, end := range t.Ends {
				if end > t.MaxTime {
					t.MaxTime = end
				}
			}
		}

		idx.byName[t.Name] = t
		idx.TotalRecords += t.Total
		idx.TotalEvents += int64(len(t.Events))

		if t.MinTime < idx.MinTime {
			idx.MinTime = t.MinTime
		}
		if t.MaxTime > idx.MaxTime {
			idx.MaxTime = t.MaxTime
		}

		// Packet and stream decoder timestamps describe the actual capture.
		// Abstract records can be created during analysis or span hours, so they
		// must not stretch the default viewport of a short PCAP.
		if t.LayerRank < int(LayerAbstract) {
			if t.Events[0].Time < idx.CaptureMin {
				idx.CaptureMin = t.Events[0].Time
			}
			if last := t.Events[len(t.Events)-1].Time; last > idx.CaptureMax {
				idx.CaptureMax = last
			}
		}

		if t.Truncated {
			idx.Truncated = true
		}
	}

	if idx.MinTime == math.MaxInt64 {
		idx.MinTime = 0
	}
	if idx.CaptureMin == math.MaxInt64 {
		idx.CaptureMin = idx.MinTime
		idx.CaptureMax = idx.MaxTime
	}

	return idx
}

// indexTimelineType reads one audit record file and builds its time index.
func indexTimelineType(path, typeName string, eventLimit int) (*tlTypeIndex, error) {
	reader, err := NewAuditRecordReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	if _, err = reader.ReadHeader(); err != nil {
		return nil, err
	}

	layer := GetLayerType(typeName)

	ti := &tlTypeIndex{
		Name:      typeName,
		Layer:     GetLayerName(layer),
		LayerRank: int(layer),
	}

	var (
		intern     = make(map[string]int32)
		ordinal    int32
		durChecked bool
		firstIdx   []int
		lastIdx    []int
		ends       []int64
	)

	add := func(s string) int32 {
		if s == "" {
			return -1
		}

		if i, ok := intern[s]; ok {
			return i
		}

		i := int32(len(ti.strings))
		ti.strings = append(ti.strings, s)
		intern[s] = i

		return i
	}

	for {
		record, readErr := reader.NextRecord()
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				ti.Truncated = true
			}
			break
		}

		current := ordinal
		ordinal++
		ti.Total++

		auditRecord, ok := record.(types.AuditRecord)
		if !ok {
			continue
		}

		if !durChecked {
			durChecked = true
			firstIdx, lastIdx = timelineDurationFields(record)
		}

		ts := auditRecord.Time()
		if ts <= 0 {
			ti.Invalid++

			continue
		}

		if len(ti.Events) >= eventLimit {
			ti.Truncated = true

			continue
		}

		ti.Events = append(ti.Events, tlEvent{
			Time:    ts,
			Ordinal: current,
			Src:     add(auditRecord.Src()),
			Dst:     add(auditRecord.Dst()),
		})

		if firstIdx != nil {
			end := timelineEndTimestamp(record, firstIdx, lastIdx, ts)
			ends = append(ends, end)

			if end > ts && end-ts > ti.MaxDuration {
				ti.MaxDuration = end - ts
			}
		}
	}

	if firstIdx != nil && len(ends) == len(ti.Events) {
		ti.Ends = ends
	}

	sort.Stable(tlSorter{events: ti.Events, ends: ti.Ends})

	return ti, nil
}

// timelineDurationFields returns the reflect field indices of the
// TimestampFirst/TimestampLast pair when the record carries a duration.
func timelineDurationFields(record any) (first, last []int) {
	v := reflect.ValueOf(record)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil, nil
	}

	t := v.Elem().Type()
	if t.Kind() != reflect.Struct {
		return nil, nil
	}

	f, okFirst := t.FieldByName("TimestampFirst")
	l, okLast := t.FieldByName("TimestampLast")

	if !okFirst || !okLast || f.Type.Kind() != reflect.Int64 || l.Type.Kind() != reflect.Int64 {
		return nil, nil
	}

	return f.Index, l.Index
}

// timelineEndTimestamp reads the validated end timestamp, or 0 when the record
// does not describe a usable interval.
func timelineEndTimestamp(record any, first, last []int, start int64) int64 {
	v := reflect.ValueOf(record).Elem()

	begin := v.FieldByIndex(first).Int()
	end := v.FieldByIndex(last).Int()

	if begin <= 0 || end <= begin || start <= 0 {
		return 0
	}

	return end
}

// tlSorter sorts events by (Time, Ordinal), keeping the parallel Ends slice aligned.
type tlSorter struct {
	events []tlEvent
	ends   []int64
}

func (s tlSorter) Len() int { return len(s.events) }

func (s tlSorter) Less(i, j int) bool {
	if s.events[i].Time != s.events[j].Time {
		return s.events[i].Time < s.events[j].Time
	}

	return s.events[i].Ordinal < s.events[j].Ordinal
}

func (s tlSorter) Swap(i, j int) {
	s.events[i], s.events[j] = s.events[j], s.events[i]

	if s.ends != nil {
		s.ends[i], s.ends[j] = s.ends[j], s.ends[i]
	}
}

// lowerBound returns the first index with Time >= ts.
func (t *tlTypeIndex) lowerBound(ts int64) int {
	return sort.Search(len(t.Events), func(i int) bool { return t.Events[i].Time >= ts })
}

// upperBound returns the first index with Time > ts.
func (t *tlTypeIndex) upperBound(ts int64) int {
	return sort.Search(len(t.Events), func(i int) bool { return t.Events[i].Time > ts })
}

// hasEvent validates a record identity in O(log n + records sharing the exact
// timestamp), preventing arbitrary ordinals from forcing a full gzip scan.
func (t *tlTypeIndex) hasEvent(ts int64, ordinal int32) bool {
	lo := t.lowerBound(ts)
	hi := t.upperBound(ts)

	for i := lo; i < hi; i++ {
		if t.Events[i].Ordinal == ordinal {
			return true
		}
	}

	return false
}
