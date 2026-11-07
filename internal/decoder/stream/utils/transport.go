package utils

import (
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// TransportRun is a framing domain bounded by transport qualification changes.
type TransportRun struct {
	Conversation *core.ConversationInfo
	Observation  string
}

// TransportRuns preserves each direction's sequence order while merging capture
// times. A qualification transition breaks both framing and request pairing.
func TransportRuns(c *core.ConversationInfo) []TransportRun {
	directions := [2]core.DataFragments{c.ClientData, c.ServerData}
	if directions[0] == nil && directions[1] == nil {
		for _, f := range c.Data {
			side := 0
			if f.Direction() == reassembly.TCPDirServerToClient {
				side = 1
			}
			directions[side] = append(directions[side], f)
		}
	}
	qualified := false
	for _, fragments := range directions {
		for _, f := range fragments {
			if d, ok := f.(*core.StreamData); ok && d.TCPObservation != "" {
				qualified = true
				break
			}
		}
	}
	if !qualified {
		return []TransportRun{{Conversation: c}}
	}
	var runs []TransportRun
	var observation [2]string
	var current *core.ConversationInfo
	for len(directions[0])+len(directions[1]) > 0 {
		side := 0
		if len(directions[0]) == 0 || len(directions[1]) > 0 && core.FragmentTime(directions[1][0]) < core.FragmentTime(directions[0][0]) {
			side = 1
		}
		f := directions[side][0]
		directions[side] = directions[side][1:]
		note := ""
		if d, ok := f.(*core.StreamData); ok {
			note = d.TCPObservation
		}
		if current == nil || note != observation[side] {
			observation[side] = note
			copy := *c
			copy.Data, copy.ClientData, copy.ServerData = nil, nil, nil
			current = &copy
			notes := observation[0]
			if observation[1] != "" && observation[1] != notes {
				notes = strings.Trim(notes+","+observation[1], ",")
			}
			runs = append(runs, TransportRun{current, notes})
		}
		current.Data = append(current.Data, f)
		if side == 0 {
			current.ClientData = append(current.ClientData, f)
		} else {
			current.ServerData = append(current.ServerData, f)
		}
	}
	return runs
}

func TransportQualification(observation string) string {
	if observation == "" {
		return ""
	}
	return observation + "; endpoint delivery unconfirmed"
}
