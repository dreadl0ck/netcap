package utils

import (
	"fmt"
	"iter"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

// Range-backed runs retain only the two iterator heads while consumers replay a run.
func WalkSourceTransportRuns(c *core.ConversationInfo, consume func(*core.ConversationInfo, string) error) error {
	if c.ClientSource == nil || c.ServerSource == nil {
		return fmt.Errorf("transport source requires directional ranges")
	}
	source := core.MergedSource{Client: c.ClientSource, Server: c.ServerSource}
	var sourceErr error
	next, stop := iter.Pull(core.SourceFragments(source, &sourceErr))
	defer stop()
	var seen, start [2]int64
	var observations [2]string
	started := false
	publish := func() error {
		if !started {
			return nil
		}
		copy := *c
		copy.Data, copy.ClientData, copy.ServerData = nil, nil, nil
		copy.ClientSource = core.FragmentRange(c.ClientSource, start[0], seen[0]-start[0])
		copy.ServerSource = core.FragmentRange(c.ServerSource, start[1], seen[1]-start[1])
		copy.Source = core.MergedSource{Client: copy.ClientSource, Server: copy.ServerSource}
		copy.LoadData = nil
		notes := observations[0]
		if observations[1] != "" && observations[1] != notes {
			notes = strings.Trim(notes+","+observations[1], ",")
		}
		if err := consume(&copy, notes); err != nil {
			return err
		}
		return copy.FragmentError
	}
	for {
		fragment, ok := next()
		if !ok {
			if sourceErr != nil {
				return sourceErr
			}
			return publish()
		}
		side := 0
		if core.FromServer(fragment) {
			side = 1
		}
		note := fragmentObservation(fragment)
		if !started || note != observations[side] {
			if err := publish(); err != nil {
				return err
			}
			start = seen
			observations[side] = note
			started = true
		}
		seen[side]++
	}
}
