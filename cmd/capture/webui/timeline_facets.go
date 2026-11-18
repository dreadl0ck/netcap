package webui

import "github.com/RoaringBitmap/roaring"

const (
	timelineFacetMaxKeys       = 4096
	timelineFacetMaxBytes      = 32 << 20
	timelineFacetCheckInterval = 16_384
)

func (t *tlTypeIndex) buildFacets() {
	t.facetsOnce.Do(func() {
		remaining := uint64(timelineFacetMaxBytes)
		if t.owner != nil {
			t.owner.facetMu.Lock()
			defer t.owner.facetMu.Unlock()
			if t.owner.facetBytes >= remaining {
				return
			}
			remaining -= t.owner.facetBytes
		}
		hosts := make(map[string]*roaring.Bitmap)
		community := make(map[string]*roaring.Bitmap)
		var keyBytes uint64
		pending := 0
		size := func() uint64 {
			bytes := keyBytes
			for _, bitmap := range hosts {
				bytes += bitmap.GetSizeInBytes()
			}
			for _, bitmap := range community {
				bytes += bitmap.GetSizeInBytes()
			}
			return bytes
		}
		add := func(postings map[string]*roaring.Bitmap, key string, position uint32) bool {
			if key == "" {
				return true
			}
			bitmap := postings[key]
			if bitmap == nil {
				keyBytes += uint64(128 + len(key))
				if len(hosts)+len(community) >= timelineFacetMaxKeys || keyBytes > remaining {
					return false
				}
				bitmap = roaring.New()
				postings[key] = bitmap
			}
			bitmap.Add(position)
			pending++
			if pending == timelineFacetCheckInterval {
				pending = 0
				return size() <= remaining
			}
			return true
		}
		for i, event := range t.Events {
			pos := uint32(i)
			if !add(hosts, t.str(event.Src), pos) || !add(hosts, t.str(event.Dst), pos) {
				return
			}
			if t.cids != nil && !add(community, t.str(t.cids[i]), pos) {
				return
			}
			for _, id := range t.extraCIDs[event.Ordinal] {
				if !add(community, t.str(id), pos) {
					return
				}
			}
		}
		bytes := size()
		if bytes > remaining {
			return
		}
		if t.owner != nil {
			t.owner.facetBytes += bytes
		}
		t.hosts, t.community = hosts, community
	})
}

func (q *timelineQuery) candidates(t *tlTypeIndex) *roaring.Bitmap {
	if q.canceled() {
		return nil
	}
	if q.Host == "" && len(q.CommunityIDs) == 0 {
		return nil
	}
	if len(q.CommunityIDs) > 0 && t.cids == nil && len(t.extraCIDs) == 0 {
		return roaring.New()
	}
	t.buildFacets()
	if t.hosts == nil {
		return nil
	}
	var selected *roaring.Bitmap
	if q.Host != "" {
		if bitmap := t.hosts[q.Host]; bitmap != nil {
			selected = bitmap.Clone()
		} else {
			selected = roaring.New()
		}
	}
	if len(q.CommunityIDs) > 0 {
		ids := roaring.New()
		for id := range q.CommunityIDs {
			if bitmap := t.community[id]; bitmap != nil {
				ids.Or(bitmap)
			}
		}
		if selected == nil {
			selected = ids
		} else {
			selected.And(ids)
		}
	}
	return selected
}

func (q *timelineQuery) nextMatch(t *tlTypeIndex, from, hi int, candidates *roaring.Bitmap) int {
	if candidates != nil {
		iter := candidates.Iterator()
		iter.AdvanceIfNeeded(uint32(from))
		for iter.HasNext() && !q.canceled() {
			i := int(iter.Next())
			if i >= hi {
				break
			}
			if q.match(t, i) {
				return i
			}
		}
		return hi
	}
	for i := from; i < hi; i++ {
		if (i-from)%256 == 0 && q.canceled() {
			return hi
		}
		if q.match(t, i) {
			return i
		}
	}
	return hi
}

func (q *timelineQuery) prevMatch(t *tlTypeIndex, from, lo int, candidates *roaring.Bitmap) int {
	if from < lo {
		return lo - 1
	}
	if candidates != nil {
		rank := candidates.Rank(uint32(from))
		for rank > 0 && !q.canceled() {
			i, _ := candidates.Select(uint32(rank - 1))
			if int(i) < lo {
				break
			}
			if q.match(t, int(i)) {
				return int(i)
			}
			rank--
		}
		return lo - 1
	}
	for i := from; i >= lo; i-- {
		if (from-i)%256 == 0 && q.canceled() {
			return lo - 1
		}
		if q.match(t, i) {
			return i
		}
	}
	return lo - 1
}

func (q *timelineQuery) eachMatch(t *tlTypeIndex, lo, hi int, visit func(int)) {
	if selected := q.candidates(t); selected != nil {
		iter := selected.Iterator()
		iter.AdvanceIfNeeded(uint32(lo))
		for iter.HasNext() && !q.canceled() {
			i := int(iter.Next())
			if i >= hi {
				break
			}
			if q.match(t, i) {
				visit(i)
			}
		}
		return
	}
	for i := lo; i < hi; i++ {
		if (i-lo)%256 == 0 && q.canceled() {
			return
		}
		if q.match(t, i) {
			visit(i)
		}
	}
}
