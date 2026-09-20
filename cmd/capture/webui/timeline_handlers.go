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
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

const (
	timelineDefaultEventLimit = 250
	timelineMaxEventLimit     = 2000
	timelineMaxBuckets        = 2000
)

// Full record retrieval must decompress from the beginning of a gzip audit
// file. Bound concurrent reads so several late-record inspections cannot
// monopolize CPU and disk.
var timelineRecordReadSlots = make(chan struct{}, 2)

// timelineTrackJSON describes one audit record type track.
type timelineTrackJSON struct {
	Type        string `json:"type"`
	Layer       string `json:"layer"`
	LayerRank   int    `json:"layerRank"`
	Count       int64  `json:"count"`
	Records     int64  `json:"records"`
	MinTime     string `json:"minTime"`
	MaxTime     string `json:"maxTime"`
	HasDuration bool   `json:"hasDuration"`
	Truncated   bool   `json:"truncated"`
	Invalid     int64  `json:"invalid"`
}

// timelineMetaJSON is the response of /api/timeline/meta.
type timelineMetaJSON struct {
	Status      string              `json:"status"`
	Error       string              `json:"error,omitempty"`
	Done        int64               `json:"done"`
	Total       int64               `json:"total"`
	Generation  string              `json:"generation,omitempty"`
	MinTime     string              `json:"minTime,omitempty"`
	MaxTime     string              `json:"maxTime,omitempty"`
	CaptureMin  string              `json:"captureMinTime,omitempty"`
	CaptureMax  string              `json:"captureMaxTime,omitempty"`
	TotalEvents int64               `json:"totalEvents"`
	Records     int64               `json:"records"`
	Truncated   bool                `json:"truncated"`
	Tracks      []timelineTrackJSON `json:"tracks"`
	OutputDir   string              `json:"outputDir,omitempty"`
}

// timelineEventJSON is one record occurrence on the timeline.
type timelineEventJSON struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Layer   string `json:"layer"`
	Time    string `json:"time"`
	End     string `json:"end,omitempty"`
	Src     string `json:"src,omitempty"`
	Dst     string `json:"dst,omitempty"`
	Ordinal int32  `json:"ordinal"`
	Cursor  string `json:"cursor"`
}

// timelineEventsJSON is the response of /api/timeline/events.
type timelineEventsJSON struct {
	Status     string              `json:"status"`
	Error      string              `json:"error,omitempty"`
	Done       int64               `json:"done"`
	Total      int64               `json:"total"`
	Generation string              `json:"generation,omitempty"`
	Start      string              `json:"start,omitempty"`
	End        string              `json:"end,omitempty"`
	Events     []timelineEventJSON `json:"events"`
	MatchCount int64               `json:"matchCount"`
	HasMore    bool                `json:"hasMore"`
	HasPrev    bool                `json:"hasPrev"`
}

// timelineBucketSeriesJSON is the density of one track across the window.
type timelineBucketSeriesJSON struct {
	Type        string  `json:"type"`
	Layer       string  `json:"layer"`
	HasDuration bool    `json:"hasDuration"`
	Counts      []int64 `json:"counts"`
	Max         int64   `json:"max"`
	Total       int64   `json:"total"`
}

// timelineBucketsJSON is the response of /api/timeline/buckets.
type timelineBucketsJSON struct {
	Status     string                     `json:"status"`
	Error      string                     `json:"error,omitempty"`
	Done       int64                      `json:"done"`
	Total      int64                      `json:"total"`
	Generation string                     `json:"generation,omitempty"`
	Start      string                     `json:"start,omitempty"`
	End        string                     `json:"end,omitempty"`
	BucketNs   string                     `json:"bucketNs,omitempty"`
	MatchCount int64                      `json:"matchCount"`
	Series     []timelineBucketSeriesJSON `json:"series"`
}

// timelineRecordJSON is the response of /api/timeline/record.
type timelineRecordJSON struct {
	Status  string          `json:"status"`
	Error   string          `json:"error,omitempty"`
	Type    string          `json:"type,omitempty"`
	Ordinal int32           `json:"ordinal"`
	Time    string          `json:"time,omitempty"`
	Src     string          `json:"src,omitempty"`
	Dst     string          `json:"dst,omitempty"`
	Record  json.RawMessage `json:"record,omitempty"`
}

// timelineIndexFromRequest resolves the output directory and its index.
func (s *Server) timelineIndexFromRequest(w http.ResponseWriter, r *http.Request) (string, timelineIndexStatus, bool) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return "", timelineIndexStatus{}, false
	}

	outDir, _ := s.resolveOutDirFromRequest(r)
	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)

		return "", timelineIndexStatus{}, false
	}

	status := timelineIndexFor(outDir)
	if expected := r.URL.Query().Get("generation"); expected != "" &&
		(status.State != timelineStateReady || status.Index == nil || status.Index.Generation != expected) {
		RespondJSON(w, http.StatusConflict, map[string]string{"status": timelineStateError, "error": "timeline generation changed"})

		return "", timelineIndexStatus{}, false
	}

	return outDir, status, true
}

// handleTimelineMeta reports the capture bounds and the available tracks.
func (s *Server) handleTimelineMeta(w http.ResponseWriter, r *http.Request) {
	outDir, status, ok := s.timelineIndexFromRequest(w, r)
	if !ok {
		return
	}

	resp := timelineMetaJSON{
		Status:    status.State,
		Error:     status.Err,
		Done:      status.Done,
		Total:     status.Total,
		Tracks:    []timelineTrackJSON{},
		OutputDir: outDir,
	}

	if status.State != timelineStateReady || status.Index == nil {
		RespondJSON(w, http.StatusOK, resp)

		return
	}

	idx := status.Index

	resp.Generation = idx.Generation
	resp.MinTime = strconv.FormatInt(idx.MinTime, 10)
	resp.MaxTime = strconv.FormatInt(idx.MaxTime, 10)
	resp.CaptureMin = strconv.FormatInt(idx.CaptureMin, 10)
	resp.CaptureMax = strconv.FormatInt(idx.CaptureMax, 10)
	resp.TotalEvents = idx.TotalEvents
	resp.Records = idx.TotalRecords
	resp.Truncated = idx.Truncated

	for _, t := range idx.Types {
		if len(t.Events) == 0 {
			continue
		}

		resp.Tracks = append(resp.Tracks, timelineTrackJSON{
			Type:        t.Name,
			Layer:       t.Layer,
			LayerRank:   t.LayerRank,
			Count:       int64(len(t.Events)),
			Records:     t.Total,
			MinTime:     strconv.FormatInt(t.MinTime, 10),
			MaxTime:     strconv.FormatInt(t.MaxTime, 10),
			HasDuration: t.hasDuration(),
			Truncated:   t.Truncated,
			Invalid:     t.Invalid,
		})
	}

	RespondJSON(w, http.StatusOK, resp)
}

// handleTimelineEvents returns a chronological page of records for a window.
func (s *Server) handleTimelineEvents(w http.ResponseWriter, r *http.Request) {
	_, status, ok := s.timelineIndexFromRequest(w, r)
	if !ok {
		return
	}

	resp := timelineEventsJSON{
		Status: status.State,
		Error:  status.Err,
		Done:   status.Done,
		Total:  status.Total,
		Events: []timelineEventJSON{},
	}

	if status.State != timelineStateReady || status.Index == nil {
		RespondJSON(w, http.StatusOK, resp)

		return
	}

	query, err := timelineQueryFromRequest(r, status.Index, timelineDefaultEventLimit, timelineMaxEventLimit)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, timelineEventsJSON{Status: timelineStateError, Error: err.Error(), Events: []timelineEventJSON{}})

		return
	}

	resp.Generation = status.Index.Generation
	resp.Start = strconv.FormatInt(query.Start, 10)
	resp.End = strconv.FormatInt(query.End, 10)
	if raw := r.URL.Query().Get("at"); raw != "" {
		at, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil {
			RespondJSON(w, http.StatusBadRequest, timelineEventsJSON{Status: timelineStateError, Error: "invalid at parameter", Events: []timelineEventJSON{}})

			return
		}

		if hit := query.nearest(at); hit != nil {
			resp.Events = append(resp.Events, timelineEventOf(*hit))
		}

		RespondJSON(w, http.StatusOK, resp)

		return
	}

	hits := query.page()

	for _, hit := range hits {
		resp.Events = append(resp.Events, timelineEventOf(hit))
	}

	if len(hits) > 0 {
		last := hits[len(hits)-1]
		probeAfter := *query
		probeAfter.After = ptrKey(query.key(last.Track, last.Index))
		probeAfter.Before = nil
		probeAfter.Limit = 1
		resp.HasMore = len(probeAfter.page()) > 0

		first := hits[0]
		probeBefore := *query
		probeBefore.Before = ptrKey(query.key(first.Track, first.Index))
		probeBefore.After = nil
		probeBefore.Limit = 1
		resp.HasPrev = len(probeBefore.page()) > 0
	}

	RespondJSON(w, http.StatusOK, resp)
}

// handleTimelineBuckets returns per-track densities for the visible window.
func (s *Server) handleTimelineBuckets(w http.ResponseWriter, r *http.Request) {
	_, status, ok := s.timelineIndexFromRequest(w, r)
	if !ok {
		return
	}

	resp := timelineBucketsJSON{
		Status: status.State,
		Error:  status.Err,
		Done:   status.Done,
		Total:  status.Total,
		Series: []timelineBucketSeriesJSON{},
	}

	if status.State != timelineStateReady || status.Index == nil {
		RespondJSON(w, http.StatusOK, resp)

		return
	}

	query, err := timelineQueryFromRequest(r, status.Index, 0, 0)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, timelineBucketsJSON{Status: timelineStateError, Error: err.Error(), Series: []timelineBucketSeriesJSON{}})

		return
	}

	count := 240
	if raw := r.URL.Query().Get("buckets"); raw != "" {
		if val, convErr := strconv.Atoi(raw); convErr == nil && val > 0 {
			count = val
		}
	}

	if count > timelineMaxBuckets {
		count = timelineMaxBuckets
	}

	series, matchCount := query.buckets(count)

	resp.Generation = status.Index.Generation
	resp.Start = strconv.FormatInt(query.Start, 10)
	resp.End = strconv.FormatInt(query.End, 10)
	resp.BucketNs = strconv.FormatInt((query.End-query.Start)/int64(count), 10)
	resp.MatchCount = matchCount

	for _, t := range query.Tracks {
		counts := series[t.Name]

		var max, total int64

		for _, c := range counts {
			if c > max {
				max = c
			}

			total += c
		}

		resp.Series = append(resp.Series, timelineBucketSeriesJSON{
			Type:        t.Name,
			Layer:       t.Layer,
			HasDuration: t.hasDuration(),
			Counts:      counts,
			Max:         max,
			Total:       total,
		})
	}

	RespondJSON(w, http.StatusOK, resp)
}

// handleTimelineRecord returns the full record behind a timeline event.
func (s *Server) handleTimelineRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	outDir, _ := s.resolveOutDirFromRequest(r)
	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)

		return
	}

	if expected := r.URL.Query().Get("generation"); expected != "" {
		status := timelineIndexFor(outDir)
		if status.State != timelineStateReady || status.Index == nil || status.Index.Generation != expected {
			RespondJSON(w, http.StatusConflict, timelineRecordJSON{Status: timelineStateError, Error: "timeline generation changed"})

			return
		}
	}

	recordType := r.URL.Query().Get("type")
	if recordType == "" || strings.ContainsAny(recordType, `/\.`) {
		RespondJSON(w, http.StatusBadRequest, timelineRecordJSON{Status: timelineStateError, Error: "invalid record type"})

		return
	}

	ordinal, err := strconv.ParseInt(r.URL.Query().Get("ordinal"), 10, 32)
	if err != nil || ordinal < 0 {
		RespondJSON(w, http.StatusBadRequest, timelineRecordJSON{Status: timelineStateError, Error: "invalid ordinal"})

		return
	}

	eventTime, err := strconv.ParseInt(r.URL.Query().Get("time"), 10, 64)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, timelineRecordJSON{Status: timelineStateError, Error: "invalid time"})

		return
	}

	indexStatus := timelineIndexFor(outDir)
	if indexStatus.State != timelineStateReady || indexStatus.Index == nil {
		RespondJSON(w, http.StatusConflict, timelineRecordJSON{Status: timelineStateError, Error: "timeline index is not ready"})

		return
	}

	track := indexStatus.Index.typeIndex(recordType)
	if track == nil || !track.hasEvent(eventTime, int32(ordinal)) {
		RespondJSON(w, http.StatusBadRequest, timelineRecordJSON{Status: timelineStateError, Error: "record is not present in the timeline index"})

		return
	}

	path := filepath.Join(outDir, recordType+defaults.FileExtension+".gz")
	if _, statErr := os.Stat(path); statErr != nil {
		path = filepath.Join(outDir, recordType+defaults.FileExtension)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		RespondJSON(w, http.StatusNotFound, timelineRecordJSON{Status: timelineStateError, Error: "audit record file not found"})

		return
	}

	select {
	case timelineRecordReadSlots <- struct{}{}:
		defer func() { <-timelineRecordReadSlots }()
	case <-r.Context().Done():
		return
	}

	reader, err := NewAuditRecordReader(path)
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, timelineRecordJSON{Status: timelineStateError, Error: err.Error()})

		return
	}
	defer reader.Close()

	if _, err = reader.ReadHeader(); err != nil {
		RespondJSON(w, http.StatusInternalServerError, timelineRecordJSON{Status: timelineStateError, Error: err.Error()})

		return
	}

	if err = reader.Skip(int(ordinal)); err != nil {
		RespondJSON(w, http.StatusNotFound, timelineRecordJSON{Status: timelineStateError, Error: "record not found"})

		return
	}

	record, err := reader.NextRecord()
	if err != nil {
		RespondJSON(w, http.StatusNotFound, timelineRecordJSON{Status: timelineStateError, Error: "record not found"})

		return
	}

	payload, err := json.Marshal(record)
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, timelineRecordJSON{Status: timelineStateError, Error: err.Error()})

		return
	}

	resp := timelineRecordJSON{
		Status:  timelineStateReady,
		Type:    recordType,
		Ordinal: int32(ordinal),
		Record:  payload,
	}

	if auditRecord, ok := record.(types.AuditRecord); ok {
		resp.Time = strconv.FormatInt(auditRecord.Time(), 10)
		resp.Src = auditRecord.Src()
		resp.Dst = auditRecord.Dst()
	}

	RespondJSON(w, http.StatusOK, resp)
}

// timelineQueryFromRequest builds a query from the request parameters, falling
// back to the full capture window.
func timelineQueryFromRequest(r *http.Request, idx *timelineIndex, defaultLimit, maxLimit int) (*timelineQuery, error) {
	q := r.URL.Query()
	if expected := q.Get("generation"); expected != "" && expected != idx.Generation {
		return nil, timelineParamError{name: "generation"}
	}

	query := &timelineQuery{
		Start:  idx.MinTime,
		End:    idx.MaxTime,
		Search: strings.ToLower(strings.TrimSpace(q.Get("q"))),
		Limit:  defaultLimit,
	}

	if raw := q.Get("start"); raw != "" {
		val, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, errTimelineBadParam("start")
		}

		query.Start = val
	}

	if raw := q.Get("end"); raw != "" {
		val, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, errTimelineBadParam("end")
		}

		query.End = val
	}

	if query.Start < idx.MinTime {
		query.Start = idx.MinTime
	}
	if query.Start > idx.MaxTime {
		query.Start = idx.MaxTime
	}
	if query.End < idx.MinTime {
		query.End = idx.MinTime
	}
	if query.End > idx.MaxTime {
		query.End = idx.MaxTime
	}
	if query.End < query.Start {
		query.Start, query.End = query.End, query.Start
	}

	if query.End == query.Start {
		if query.End < idx.MaxTime {
			query.End++
		} else if query.Start > idx.MinTime {
			query.Start--
		}
	}

	if maxLimit > 0 {
		if raw := q.Get("limit"); raw != "" {
			val, err := strconv.Atoi(raw)
			if err != nil || val <= 0 {
				return nil, errTimelineBadParam("limit")
			}

			query.Limit = val
		}

		if query.Limit > maxLimit {
			query.Limit = maxLimit
		}
	}

	after, err := decodeTimelineCursor(q.Get("after"))
	if err != nil {
		return nil, err
	}

	before, err := decodeTimelineCursor(q.Get("before"))
	if err != nil {
		return nil, err
	}

	query.After = after
	query.Before = before
	if after != nil && before != nil {
		return nil, errTimelineBadParam("pagination")
	}
	if (after != nil || before != nil) && q.Get("generation") == "" {
		return nil, timelineParamError{name: "generation"}
	}

	query.Tracks = timelineTracksFor(idx, q.Get("types"))

	return query, nil
}

// timelineTracksFor resolves the requested track names, defaulting to all.
func timelineTracksFor(idx *timelineIndex, raw string) []*tlTypeIndex {
	if strings.TrimSpace(raw) == "" {
		return idx.Types
	}

	tracks := make([]*tlTypeIndex, 0, len(idx.Types))
	wanted := make(map[string]bool)

	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			wanted[name] = true
		}
	}

	for _, t := range idx.Types {
		if wanted[t.Name] {
			tracks = append(tracks, t)
		}
	}

	return tracks
}

func timelineEventOf(hit timelineHit) timelineEventJSON {
	t := hit.Track
	e := t.Events[hit.Index]

	event := timelineEventJSON{
		ID:      t.Name + ":" + strconv.FormatInt(int64(e.Ordinal), 10),
		Type:    t.Name,
		Layer:   t.Layer,
		Time:    strconv.FormatInt(e.Time, 10),
		Src:     t.str(e.Src),
		Dst:     t.str(e.Dst),
		Ordinal: e.Ordinal,
		Cursor: tlKey{
			Time:      e.Time,
			LayerRank: t.LayerRank,
			Type:      t.Name,
			Ordinal:   e.Ordinal,
		}.encode(),
	}

	if t.hasDuration() && t.Ends[hit.Index] > e.Time {
		event.End = strconv.FormatInt(t.Ends[hit.Index], 10)
	}

	return event
}

func ptrKey(k tlKey) *tlKey { return &k }

type timelineParamError struct{ name string }

func (e timelineParamError) Error() string { return "invalid " + e.name + " parameter" }

func errTimelineBadParam(name string) error { return timelineParamError{name: name} }
