package webui

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"
)

const (
	connectionCacheSize  = 3
	connectionCacheBytes = 64 << 20
	connectionMaxRows    = 200_000
	connectionMaxKeys    = 8192
)

type connectionFilter struct {
	layer, ipVersion, host, srcIP, dstIP, protocol string
	communityIDs                                   map[string]bool
	offset, limit                                  int
	observationID                                  string
	snapshotSequence                               uint64
}

func parseConnectionFilter(q url.Values) (connectionFilter, error) {
	opts := connectionFilter{
		layer: q.Get("layer"), ipVersion: q.Get("ipVersion"),
		host: q.Get("host"), srcIP: q.Get("srcIP"), dstIP: q.Get("dstIP"), protocol: q.Get("protocol"),
	}
	if q.Has("observationId") || q.Has("snapshotSequence") {
		if len(q["observationId"]) != 1 || len(q["snapshotSequence"]) != 1 {
			return opts, errors.New("exact connection selection requires one observationId and snapshotSequence")
		}
		opts.observationID = q.Get("observationId")
		if len(opts.observationID) != 64 || strings.Trim(opts.observationID, "0123456789abcdef") != "" {
			return opts, errors.New("invalid connection observation identity")
		}
		sequence, err := strconv.ParseUint(q.Get("snapshotSequence"), 10, 64)
		if err != nil || sequence == 0 {
			return opts, errors.New("invalid connection snapshot sequence")
		}
		opts.snapshotSequence = sequence
	}
	if opts.layer == "" {
		opts.layer = "all"
	}
	if opts.ipVersion == "" {
		opts.ipVersion = "all"
	}
	if _, present := q["limit"]; present {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 || n > 1000 {
			return opts, errors.New("limit must be between 1 and 1000")
		}
		opts.limit = n
	}
	if _, present := q["offset"]; present {
		n, err := strconv.Atoi(q.Get("offset"))
		if err != nil || n < 0 {
			return opts, errors.New("offset must be non-negative")
		}
		opts.offset = n
	}
	if len(q["communityId"]) > 0 {
		opts.communityIDs = make(map[string]bool)
		for _, id := range q["communityId"] {
			if id = strings.TrimSpace(id); id != "" {
				opts.communityIDs[id] = true
			}
		}
	}
	return opts, nil
}

func (f connectionFilter) match(row ConnectionSummary) bool {
	if f.observationID != "" && (row.ObservationID != f.observationID || row.SnapshotSequence != f.snapshotSequence) {
		return false
	}
	if f.layer != "" && f.layer != "all" && f.layer != "transport" && f.layer != "network" ||
		f.ipVersion != "" && f.ipVersion != "all" && f.ipVersion != "ipv4" && f.ipVersion != "ipv6" {
		return false
	}
	if f.layer == "transport" && row.TransportProto == "" || f.layer == "network" && row.TransportProto != "" {
		return false
	}
	if f.ipVersion == "ipv4" && row.NetworkProto != "IPv4" || f.ipVersion == "ipv6" && row.NetworkProto != "IPv6" {
		return false
	}
	if f.host != "" && row.SrcIP != f.host && row.DstIP != f.host || f.srcIP != "" && row.SrcIP != f.srcIP || f.dstIP != "" && row.DstIP != f.dstIP {
		return false
	}
	if f.protocol != "" && row.TransportProto != f.protocol && row.ApplicationProto != f.protocol {
		return false
	}
	return len(f.communityIDs) == 0 || row.CommunityID != "" && f.communityIDs[row.CommunityID]
}

type connectionSnapshot struct {
	rows         []ConnectionSummary
	byID, byHost map[string]*roaring.Bitmap
	byProtocol   map[string]*roaring.Bitmap
	bytes        uint64
}

func newConnectionSnapshot(rows []ConnectionSummary) *connectionSnapshot {
	s := &connectionSnapshot{rows: rows}
	if len(rows) <= connectionMaxRows {
		s.byID = make(map[string]*roaring.Bitmap)
		s.byHost = make(map[string]*roaring.Bitmap)
		s.byProtocol = make(map[string]*roaring.Bitmap)
	}
	add := func(postings map[string]*roaring.Bitmap, key string, i int) bool {
		if key == "" {
			return true
		}
		bitmap := postings[key]
		if bitmap == nil {
			if len(s.byID)+len(s.byHost)+len(s.byProtocol) >= connectionMaxKeys {
				return false
			}
			bitmap = roaring.New()
			postings[key] = bitmap
		}
		bitmap.Add(uint32(i))
		return true
	}
	for i, row := range rows {
		s.bytes += uint64(320 + len(row.SrcIP) + len(row.DstIP) + len(row.CommunityID) + len(row.Sni))
		for _, app := range row.Applications {
			s.bytes += uint64(16 + len(app))
		}
		if s.byID != nil && (!add(s.byID, row.CommunityID, i) || !add(s.byHost, row.SrcIP, i) ||
			!add(s.byHost, row.DstIP, i) || !add(s.byProtocol, row.TransportProto, i) || !add(s.byProtocol, row.ApplicationProto, i)) {
			s.byID, s.byHost, s.byProtocol = nil, nil, nil
		}
	}
	for _, postings := range []map[string]*roaring.Bitmap{s.byID, s.byHost, s.byProtocol} {
		for key, bitmap := range postings {
			s.bytes += uint64(128+len(key)) + bitmap.GetSizeInBytes()
		}
	}
	return s
}

func (s *connectionSnapshot) selectRows(f connectionFilter) ConnectionsResponse {
	var selected *roaring.Bitmap
	if s.byID != nil {
		intersect := func(bitmap *roaring.Bitmap) {
			if bitmap == nil {
				bitmap = roaring.New()
			}
			if selected == nil {
				selected = bitmap.Clone()
			} else {
				selected.And(bitmap)
			}
		}
		if len(f.communityIDs) > 0 {
			ids := roaring.New()
			for id := range f.communityIDs {
				if bitmap := s.byID[id]; bitmap != nil {
					ids.Or(bitmap)
				}
			}
			intersect(ids)
		}
		if f.host != "" {
			intersect(s.byHost[f.host])
		}
		if f.srcIP != "" {
			intersect(s.byHost[f.srcIP])
		}
		if f.dstIP != "" {
			intersect(s.byHost[f.dstIP])
		}
		if f.protocol != "" {
			intersect(s.byProtocol[f.protocol])
		}
	}
	response := ConnectionsResponse{Connections: []ConnectionSummary{}}
	appendRow := func(row ConnectionSummary) {
		if !f.match(row) {
			return
		}
		if response.TotalCount >= f.offset && (f.limit == 0 || len(response.Connections) < f.limit) {
			response.Connections = append(response.Connections, row)
		}
		response.TotalCount++
	}
	if selected != nil {
		iter := selected.Iterator()
		for iter.HasNext() {
			appendRow(s.rows[iter.Next()])
		}
	} else {
		for _, row := range s.rows {
			appendRow(row)
		}
	}
	return response
}

type connectionCacheEntry struct {
	generation string
	used       time.Time
	ready      chan struct{}
	snapshot   *connectionSnapshot
}

var connectionCache = struct {
	sync.Mutex
	entries map[string]*connectionCacheEntry
	bytes   uint64
}{entries: make(map[string]*connectionCacheEntry)}

func connectionGeneration(outDir string) (string, error) {
	info, err := os.Stat(filepath.Join(outDir, "Connection.ncap.gz"))
	if errors.Is(err, os.ErrNotExist) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}

func connectionSnapshotFor(outDir string) (*connectionSnapshot, error) {
	for attempt := 0; attempt < 2; attempt++ {
		generation, err := connectionGeneration(outDir)
		if err != nil {
			return nil, err
		}
		connectionCache.Lock()
		entry := connectionCache.entries[outDir]
		if entry == nil || entry.generation != generation {
			if entry != nil {
				select {
				case <-entry.ready:
					if entry.snapshot != nil {
						connectionCache.bytes -= entry.snapshot.bytes
					}
				default:
				}
			}
			entry = &connectionCacheEntry{generation: generation, ready: make(chan struct{})}
			connectionCache.entries[outDir] = entry
			connectionCache.Unlock()
			rows, buildErr := readConnections(outDir)
			connectionCache.Lock()
			if buildErr == nil {
				entry.snapshot = newConnectionSnapshot(rows)
			}
			close(entry.ready)
			if connectionCache.entries[outDir] == entry {
				if buildErr != nil || entry.snapshot.bytes > connectionCacheBytes {
					delete(connectionCache.entries, outDir)
				} else {
					entry.used = time.Now()
					connectionCache.bytes += entry.snapshot.bytes
					connectionEvictLocked()
				}
			}
			connectionCache.Unlock()
			if buildErr != nil {
				return nil, buildErr
			}
		} else {
			entry.used = time.Now()
			connectionCache.Unlock()
			<-entry.ready
			if entry.snapshot == nil {
				continue
			}
		}
		after, err := connectionGeneration(outDir)
		if err != nil {
			return nil, err
		}
		if after == generation {
			return entry.snapshot, nil
		}
	}
	rows, err := readConnections(outDir)
	if err != nil {
		return nil, err
	}
	return newConnectionSnapshot(rows), nil
}

func cachedConnectionRows(outDir string) []ConnectionSummary {
	snapshot, err := connectionSnapshotFor(outDir)
	if err != nil {
		return nil
	}
	return snapshot.rows
}

func connectionEvictLocked() {
	for len(connectionCache.entries) > connectionCacheSize || connectionCache.bytes > connectionCacheBytes {
		var oldestKey string
		var oldest time.Time
		for key, entry := range connectionCache.entries {
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
		connectionCache.bytes -= connectionCache.entries[oldestKey].snapshot.bytes
		delete(connectionCache.entries, oldestKey)
	}
}
