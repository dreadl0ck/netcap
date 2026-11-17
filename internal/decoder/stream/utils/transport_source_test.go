package utils

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/gopacket/gopacket"
)

type countedRanges struct {
	data  core.SliceSource
	reads *int
}

func (s countedRanges) Count() int64 { return s.data.Count() }
func (s countedRanges) Walk(yield func(core.DataFragment) bool) error {
	return s.WalkRange(0, s.Count(), yield)
}
func (s countedRanges) WalkRange(start, count int64, yield func(core.DataFragment) bool) error {
	return s.data.WalkRange(start, count, func(fragment core.DataFragment) bool { *s.reads++; return yield(fragment) })
}

func TestSourceTransportRunsReplayOnlyTheirIndexedRanges(t *testing.T) {
	var data core.DataFragments
	for index := range 2000 {
		note := ""
		if index%2 == 1 {
			note = "after-rst"
		}
		data = append(data, &core.StreamData{RawData: []byte("x"), TCPObservation: note, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, int64(index))}})
	}
	reads, runs, rows := 0, 0, 0
	c := &core.ConversationInfo{ClientSource: countedRanges{core.SliceSource(data), &reads}, ServerSource: core.SliceSource(nil)}
	err := WalkSourceTransportRuns(c, func(run *core.ConversationInfo, _ string) error {
		runs++
		for range run.Fragments() {
			rows++
		}
		return run.FragmentError
	})
	if err != nil || runs != 2000 || rows != 2000 || reads != 4000 {
		t.Fatal("transport run replay rescanned earlier ranges", runs, rows, reads, err)
	}
}
