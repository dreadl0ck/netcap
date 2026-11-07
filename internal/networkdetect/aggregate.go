package networkdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dreadl0ck/netcap/types"
)

const maxAggregateExamples = 8

type aggregate struct {
	alert *types.Alert
}

// Windows are [first match, first match + dedupNS). Capture time alone advances
// them, including in live capture: an idle input retains pending rows until
// the next event or Flush at shutdown. Capacity flushes preserve every match.
type aggregator struct {
	windowNS    int64
	maxKeys     int
	pending     map[string]*aggregate
	matches     uint64
	capacity    uint64
	oldest      int64
	oldestKnown bool
}

func newAggregator(c Config) *aggregator {
	return &aggregator{windowNS: c.DedupNS, maxKeys: c.MaxKeys, pending: make(map[string]*aggregate)}
}

func stableKey(parts ...any) string {
	data, _ := json.Marshal(parts)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func boundedText(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

// Examples retain bounded structured context, never application payloads.
func alertExample(a *types.Alert) string {
	var evidence Evidence
	_ = json.Unmarshal([]byte(a.MatchedRecord), &evidence)
	samples := evidence.Samples
	if len(samples) > maxAggregateExamples {
		samples = samples[:maxAggregateExamples]
	}
	bounded := make([]string, 0, len(samples))
	for _, s := range samples {
		bounded = append(bounded, boundedText(s, 128))
	}
	data, _ := json.Marshal(struct {
		At          int64    `json:"at"`
		SrcIP       string   `json:"srcIP"`
		SrcPort     string   `json:"srcPort"`
		DstIP       string   `json:"dstIP"`
		DstPort     string   `json:"dstPort"`
		Domain      string   `json:"domain,omitempty"`
		CommunityID string   `json:"communityID,omitempty"`
		Observed    uint64   `json:"observed"`
		FirstSeen   int64    `json:"firstSeen"`
		Samples     []string `json:"samples"`
	}{a.Timestamp, a.SrcIP, a.SrcPort, a.DstIP, a.DstPort, a.Domain, a.CommunityID, evidence.Observed, evidence.FirstSeen, bounded})
	return string(data)
}

func (g *aggregator) add(key string, a *types.Alert) []*types.Alert {
	g.matches++
	var out []*types.Alert
	entry := g.pending[key]
	if entry == nil {
		if len(g.pending) >= g.maxKeys {
			keys := g.orderedKeys()
			out = append(out, g.take(keys[0], "capacity"))
			g.capacity++
		}
		a.AggregateKey, a.FirstSeen, a.LastSeen = key, a.Timestamp, a.Timestamp
		a.TimestampBasis = "capture-time"
		entry = &aggregate{alert: a}
		g.pending[key] = entry
		if len(g.pending) == 1 || g.oldestKnown && a.FirstSeen < g.oldest {
			g.oldest, g.oldestKnown = a.FirstSeen, true
		}
	}
	example := alertExample(a)
	row := entry.alert
	row.Count++
	row.LastSeen = a.Timestamp
	if len(row.Examples) < maxAggregateExamples {
		row.Examples = append(row.Examples, example)
	} else {
		row.Examples[maxAggregateExamples-1] = example
	}
	if g.windowNS == 0 {
		out = append(out, g.take(key, "immediate"))
	}
	return out
}

func (g *aggregator) orderedKeys() []string {
	keys := make([]string, 0, len(g.pending))
	for k := range g.pending {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := g.pending[keys[i]].alert, g.pending[keys[j]].alert
		if a.FirstSeen != b.FirstSeen {
			return a.FirstSeen < b.FirstSeen
		}
		return keys[i] < keys[j]
	})
	return keys
}

func (g *aggregator) take(key, reason string) *types.Alert {
	a := g.pending[key].alert
	delete(g.pending, key)
	g.oldestKnown = false
	a.Notes = fmt.Sprintf("aggregation=capture-time; windowNS=%d; flush=%s; Count=matching detector observations; MatchedRecord=first match; Examples=first seven plus latest", g.windowNS, reason)
	return a
}

func (g *aggregator) advance(at int64) []*types.Alert {
	if !g.oldestKnown {
		for _, entry := range g.pending {
			if !g.oldestKnown || entry.alert.FirstSeen < g.oldest {
				g.oldest, g.oldestKnown = entry.alert.FirstSeen, true
			}
		}
	}
	if !g.oldestKnown || at-g.oldest < g.windowNS {
		return nil
	}
	var out []*types.Alert
	for _, k := range g.orderedKeys() {
		if at-g.pending[k].alert.FirstSeen >= g.windowNS {
			out = append(out, g.take(k, "window"))
		}
	}
	return out
}

func (g *aggregator) flush() []*types.Alert {
	var out []*types.Alert
	for _, k := range g.orderedKeys() {
		out = append(out, g.take(k, "eof"))
	}
	return out
}
