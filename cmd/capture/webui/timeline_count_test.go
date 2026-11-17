package webui

import "testing"

func TestTimelineDurationCountIncludesOverlaps(t *testing.T) {
	track := &tlTypeIndex{
		Events: []tlEvent{{Time: 1}, {Time: 2}, {Time: 5}, {Time: 9}},
		Ends:   []int64{4, 5, 6, 20}, MaxDuration: 11,
	}
	for _, tc := range []struct{ start, end, want int64 }{{0, 20, 4}, {5, 5, 2}, {7, 8, 0}, {12, 13, 1}, {21, 23, 0}} {
		q := timelineQuery{Start: tc.start, End: tc.end, Tracks: []*tlTypeIndex{track}, Limit: 1, After: &tlKey{Time: 99}}
		if got := q.count(); got != tc.want {
			t.Errorf("window %d..%d: got %d, want %d", tc.start, tc.end, got, tc.want)
		}
	}
}

func BenchmarkTimelineDurationCount(b *testing.B) {
	const records = 200000
	track := &tlTypeIndex{Events: make([]tlEvent, records), Ends: make([]int64, records), MaxDuration: 10}
	for i := range track.Events {
		track.Events[i].Time = int64(i)
		track.Ends[i] = int64(i + 10)
	}
	q := timelineQuery{Start: 100, End: records - 1, Tracks: []*tlTypeIndex{track}}
	b.Run("bounds", func(b *testing.B) {
		for b.Loop() {
			_ = q.count()
		}
	})
	b.Run("scan", func(b *testing.B) {
		for b.Loop() {
			lo, hi := q.scanRange(track)
			var count int
			q.eachMatch(track, lo, hi, func(int) { count++ })
			if count != records-90 {
				b.Fatal(count)
			}
		}
	})
}
