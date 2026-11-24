package utils

import (
	"fmt"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// markedSlice indexes its marks like the TCP reader and counts fragments read.
type markedSlice struct {
	data  core.SliceSource
	read  *int
	index bool
}

func (s markedSlice) Count() int64 { return s.data.Count() }
func (s markedSlice) Walk(yield func(core.DataFragment) bool) error {
	return s.WalkRange(0, s.Count(), yield)
}
func (s markedSlice) WalkRange(start, count int64, yield func(core.DataFragment) bool) error {
	return s.data.WalkRange(start, count, func(f core.DataFragment) bool { *s.read++; return yield(f) })
}
func (s markedSlice) FragmentMarks() ([]core.FragmentMark, bool) {
	if !s.index {
		return nil, false
	}
	var marks []core.FragmentMark
	var payloadEnd int64
	for i, f := range s.data {
		d := f.(*core.StreamData)
		if d.SkippedBytes != 0 || d.DiscardedBytes > 0 || d.DiscardReason != "" || d.TCPObservation != "" {
			marks = append(marks, core.FragmentMark{Index: int64(i), PayloadEnd: payloadEnd})
		}
		if len(d.RawData) > 0 {
			payloadEnd = int64(i) + 1
		}
	}
	return marks, true
}

func gapRunsSummary(t *testing.T, source core.RangedFragmentSource) string {
	t.Helper()
	out := ""
	if err := WalkSourceGapRuns(source, func(run core.RangedFragmentSource, lost, unknown bool) error {
		out += fmt.Sprintf("[%d %v %v]", run.Count(), lost, unknown)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMarkedSourcesSkipPayloadWalks(t *testing.T) {
	payload := func(n int, dir reassembly.TCPFlowDirection) core.SliceSource {
		var s core.SliceSource
		for range n {
			s = append(s, &core.StreamData{RawData: []byte("x"), Dir: dir})
		}
		return s
	}
	server := payload(1000, reassembly.TCPDirServerToClient)
	shapes := map[string]core.SliceSource{
		"clean":           server,
		"unknown-start":   append(core.SliceSource{&core.StreamData{SkippedBytes: -1}}, server...),
		"internal-loss":   append(append(append(core.SliceSource{}, server[:400]...), &core.StreamData{SkippedBytes: 9}), server[400:]...),
		"discard-marker":  append(append(append(core.SliceSource{}, server[:10]...), &core.StreamData{DiscardReason: "budget", DiscardedBytes: 4}), server[10:]...),
		"late-unknown":    append(append(append(core.SliceSource{}, server[:3]...), &core.StreamData{SkippedBytes: -1}), server[3:]...),
		"empty-unknown":   append(core.SliceSource{&core.StreamData{}, &core.StreamData{SkippedBytes: -1}}, server...),
		"observation":     append(append(append(core.SliceSource{}, server[:5]...), &core.StreamData{RawData: []byte("y"), TCPObservation: "after-rst"}), server[5:]...),
		"marker-no-bytes": append(core.SliceSource{&core.StreamData{DiscardReason: "budget"}}, server...),
	}
	for name, data := range shapes {
		t.Run(name, func(t *testing.T) {
			var walked, indexed int
			want := gapRunsSummary(t, markedSlice{data: data, read: &walked})
			if got := gapRunsSummary(t, markedSlice{data: data, read: &indexed, index: true}); got != want {
				t.Fatalf("indexed gap runs %s, walked %s", got, want)
			}
			if indexed > 16 {
				t.Fatalf("indexed gap runs read %d fragments", indexed)
			}
		})
	}

	var read int
	client := markedSlice{data: payload(3, reassembly.TCPDirClientToServer), read: &read, index: true}
	lossy := append(append(append(core.SliceSource{}, server[:400]...), &core.StreamData{SkippedBytes: 9, Dir: reassembly.TCPDirServerToClient}), server[400:]...)
	conversation := &core.ConversationInfo{ClientSource: client, ServerSource: markedSlice{data: lossy, read: &read, index: true}}
	runs := 0
	if err := WalkSourceTransportRuns(conversation, func(run *core.ConversationInfo, note string) error {
		runs++
		if run.ClientSource.Count() != 3 || run.ServerSource.Count() != 1001 || note != "" {
			return fmt.Errorf("single run %d/%d %q", run.ClientSource.Count(), run.ServerSource.Count(), note)
		}
		return nil
	}); err != nil || runs != 1 {
		t.Fatal(runs, err)
	}
	if read > 4 {
		t.Fatalf("transport runs read %d fragments to find one run", read)
	}
}
