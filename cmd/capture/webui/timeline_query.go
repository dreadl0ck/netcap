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
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// tlKey is the total order used to walk audit records chronologically:
// timestamp first, then layer and type so equal timestamps stay deterministic,
// then the record ordinal within its file.
type tlKey struct {
	Time      int64
	LayerRank int
	Type      string
	Ordinal   int32
}

func (k tlKey) less(o tlKey) bool {
	if k.Time != o.Time {
		return k.Time < o.Time
	}

	if k.LayerRank != o.LayerRank {
		return k.LayerRank < o.LayerRank
	}

	if k.Type != o.Type {
		return k.Type < o.Type
	}

	return k.Ordinal < o.Ordinal
}

func (k tlKey) encode() string {
	raw := strconv.FormatInt(k.Time, 10) + "|" +
		strconv.Itoa(k.LayerRank) + "|" +
		k.Type + "|" +
		strconv.FormatInt(int64(k.Ordinal), 10)

	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeTimelineCursor(s string) (*tlKey, error) {
	if s == "" {
		return nil, nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("malformed cursor")
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 {
		return nil, errors.New("malformed cursor")
	}

	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, errors.New("malformed cursor")
	}

	rank, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, errors.New("malformed cursor")
	}

	ordinal, err := strconv.ParseInt(parts[3], 10, 32)
	if err != nil {
		return nil, errors.New("malformed cursor")
	}

	return &tlKey{Time: ts, LayerRank: rank, Type: parts[2], Ordinal: int32(ordinal)}, nil
}

// timelineQuery is one resolved request against a built index.
type timelineQuery struct {
	Start  int64
	End    int64
	Tracks []*tlTypeIndex
	Search string // already lowercased
	Limit  int
	After  *tlKey
	Before *tlKey
}

// scanRange returns the [lo, hi) window of a track that can contain matches.
// Duration tracks start earlier because a record may begin before the window
// and still overlap it.
func (q *timelineQuery) scanRange(t *tlTypeIndex) (int, int) {
	start := q.Start

	if t.hasDuration() && t.MaxDuration > 0 {
		if start > t.MaxDuration {
			start -= t.MaxDuration
		} else {
			start = 0
		}
	}

	return t.lowerBound(start), t.upperBound(q.End)
}

// match reports whether event i of track t belongs to the query result.
func (q *timelineQuery) match(t *tlTypeIndex, i int) bool {
	e := t.Events[i]

	if e.Time > q.End {
		return false
	}

	if e.Time < q.Start {
		// Only duration records may start before the window.
		if !t.hasDuration() || t.Ends[i] < q.Start {
			return false
		}
	}

	if q.Search == "" {
		return true
	}

	if strings.Contains(strings.ToLower(t.Name), q.Search) {
		return true
	}

	if strings.Contains(strings.ToLower(t.str(e.Src)), q.Search) {
		return true
	}

	return strings.Contains(strings.ToLower(t.str(e.Dst)), q.Search)
}

func (q *timelineQuery) key(t *tlTypeIndex, i int) tlKey {
	return tlKey{Time: t.Events[i].Time, LayerRank: t.LayerRank, Type: t.Name, Ordinal: t.Events[i].Ordinal}
}

// count returns the number of records matching the query window and filters,
// ignoring pagination.
func (q *timelineQuery) count() int64 {
	var total int64

	for _, t := range q.Tracks {
		lo, hi := q.scanRange(t)

		for i := lo; i < hi; i++ {
			if q.match(t, i) {
				total++
			}
		}
	}

	return total
}

// nearest returns the event whose start timestamp is closest to at. It uses
// binary search per track, then walks only as far as needed to satisfy text
// filters. Equal distances use the same deterministic ordering as pagination.
func (q *timelineQuery) nearest(at int64) *timelineHit {
	var best *timelineHit
	var bestDistance uint64

	for _, t := range q.Tracks {
		lo, hi := q.scanRange(t)
		if lo >= hi {
			continue
		}

		pos := sort.Search(hi-lo, func(i int) bool { return t.Events[lo+i].Time >= at }) + lo

		for _, direction := range []int{-1, 1} {
			i := pos
			if direction < 0 {
				i--
			}

			for i >= lo && i < hi {
				if q.match(t, i) {
					distance := timelineDistance(t.Events[i].Time, at)
					candidate := timelineHit{Track: t, Index: i}

					if best == nil || distance < bestDistance ||
						(distance == bestDistance && q.key(t, i).less(q.key(best.Track, best.Index))) {
						best = &candidate
						bestDistance = distance
					}

					break
				}

				i += direction
			}
		}
	}

	return best
}

func timelineDistance(a, b int64) uint64 {
	if a >= b {
		return uint64(a - b)
	}

	return uint64(b - a)
}

// compareTrackKey orders two tracks the way tlKey does for equal timestamps.
func compareTrackKey(rankA int, nameA string, rankB int, nameB string) int {
	if rankA != rankB {
		if rankA < rankB {
			return -1
		}

		return 1
	}

	return strings.Compare(nameA, nameB)
}

// forwardStart positions a track after the given cursor.
func (q *timelineQuery) forwardStart(t *tlTypeIndex, lo int, after *tlKey) int {
	if after == nil {
		return lo
	}

	pos := t.lowerBound(after.Time)
	if pos < lo {
		pos = lo
	}

	switch compareTrackKey(t.LayerRank, t.Name, after.LayerRank, after.Type) {
	case -1:
		// Same timestamp sorts before the cursor for this track: skip the block.
		if p := t.upperBound(after.Time); p > pos {
			pos = p
		}
	case 0:
		hiT := t.upperBound(after.Time)
		block := t.Events[pos:hiT]
		skip := sort.Search(len(block), func(i int) bool { return block[i].Ordinal > after.Ordinal })
		pos += skip
	}

	return pos
}

// backwardEnd returns the exclusive upper bound of a track before the cursor.
func (q *timelineQuery) backwardEnd(t *tlTypeIndex, hi int, before *tlKey) int {
	if before == nil {
		return hi
	}

	pos := t.upperBound(before.Time)
	if pos > hi {
		pos = hi
	}

	switch compareTrackKey(t.LayerRank, t.Name, before.LayerRank, before.Type) {
	case 1:
		// Same timestamp sorts after the cursor for this track: drop the block.
		if p := t.lowerBound(before.Time); p < pos {
			pos = p
		}
	case 0:
		loT := t.lowerBound(before.Time)
		block := t.Events[loT:pos]
		keep := sort.Search(len(block), func(i int) bool { return block[i].Ordinal >= before.Ordinal })
		pos = loT + keep
	}

	return pos
}

// timelineHit is one resolved event returned by the merge.
type timelineHit struct {
	Track *tlTypeIndex
	Index int
}

// page walks the merged chronological order and returns up to Limit events.
// With Before set it walks backwards and returns the page preceding the cursor,
// still in ascending order.
func (q *timelineQuery) page() []timelineHit {
	if q.Before != nil {
		return q.pageBackward()
	}

	return q.pageForward()
}

func (q *timelineQuery) pageForward() []timelineHit {
	type cursor struct {
		track *tlTypeIndex
		pos   int
		hi    int
	}

	cursors := make([]cursor, 0, len(q.Tracks))

	for _, t := range q.Tracks {
		lo, hi := q.scanRange(t)
		pos := q.forwardStart(t, lo, q.After)

		for pos < hi && !q.match(t, pos) {
			pos++
		}

		if pos < hi {
			cursors = append(cursors, cursor{track: t, pos: pos, hi: hi})
		}
	}

	hits := make([]timelineHit, 0, q.Limit)

	for len(hits) < q.Limit {
		best := -1

		for i := range cursors {
			if best == -1 || q.key(cursors[i].track, cursors[i].pos).less(q.key(cursors[best].track, cursors[best].pos)) {
				best = i
			}
		}

		if best == -1 {
			break
		}

		hits = append(hits, timelineHit{Track: cursors[best].track, Index: cursors[best].pos})

		pos := cursors[best].pos + 1
		for pos < cursors[best].hi && !q.match(cursors[best].track, pos) {
			pos++
		}

		if pos >= cursors[best].hi {
			cursors = append(cursors[:best], cursors[best+1:]...)

			continue
		}

		cursors[best].pos = pos
	}

	return hits
}

func (q *timelineQuery) pageBackward() []timelineHit {
	type cursor struct {
		track *tlTypeIndex
		pos   int
		lo    int
	}

	cursors := make([]cursor, 0, len(q.Tracks))

	for _, t := range q.Tracks {
		lo, hi := q.scanRange(t)
		pos := q.backwardEnd(t, hi, q.Before) - 1

		for pos >= lo && !q.match(t, pos) {
			pos--
		}

		if pos >= lo {
			cursors = append(cursors, cursor{track: t, pos: pos, lo: lo})
		}
	}

	hits := make([]timelineHit, 0, q.Limit)

	for len(hits) < q.Limit {
		best := -1

		for i := range cursors {
			if best == -1 || q.key(cursors[best].track, cursors[best].pos).less(q.key(cursors[i].track, cursors[i].pos)) {
				best = i
			}
		}

		if best == -1 {
			break
		}

		hits = append(hits, timelineHit{Track: cursors[best].track, Index: cursors[best].pos})

		pos := cursors[best].pos - 1
		for pos >= cursors[best].lo && !q.match(cursors[best].track, pos) {
			pos--
		}

		if pos < cursors[best].lo {
			cursors = append(cursors[:best], cursors[best+1:]...)

			continue
		}

		cursors[best].pos = pos
	}

	// Collected newest first; callers expect ascending order.
	for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
		hits[i], hits[j] = hits[j], hits[i]
	}

	return hits
}

// buckets returns per-track density counts across the query window. Duration
// records increment every bucket they overlap so bars stay visible when zoomed out.
func (q *timelineQuery) buckets(count int) (map[string][]int64, int64) {
	out := make(map[string][]int64, len(q.Tracks))
	var matchCount int64

	span := q.End - q.Start
	if span <= 0 || count <= 0 {
		return out, 0
	}

	for _, t := range q.Tracks {
		counts := make([]int64, count)
		delta := make([]int64, count+1)
		lo, hi := q.scanRange(t)

		for i := lo; i < hi; i++ {
			if !q.match(t, i) {
				continue
			}
			matchCount++

			start := t.Events[i].Time
			end := start

			if t.hasDuration() && t.Ends[i] > start {
				end = t.Ends[i]
			}

			from := timelineBucketOf(start, q.Start, span, count)
			to := timelineBucketOf(end, q.Start, span, count)

			delta[from]++
			if to+1 < len(delta) {
				delta[to+1]--
			}
		}

		var active int64
		for i := range counts {
			active += delta[i]
			counts[i] = active
		}

		out[t.Name] = counts
	}

	return out, matchCount
}

// timelineBucketOf maps a timestamp onto a bucket index, clamped to the window.
func timelineBucketOf(ts, start, span int64, count int) int {
	if ts <= start {
		return 0
	}

	idx := int(float64(ts-start) / float64(span) * float64(count))
	if idx >= count {
		idx = count - 1
	}

	if idx < 0 {
		idx = 0
	}

	return idx
}
