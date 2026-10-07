package flow

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var ErrAmbiguousLegacy = errors.New("ambiguous legacy connection observations")

type Query struct {
	StartNs    int64  `json:"startNs,string"`
	EndNs      int64  `json:"endNs,string"`
	Expression string `json:"expression"`
	GroupBy    string `json:"groupBy"`
	SortBy     string `json:"sortBy"`
	Limit      int    `json:"limit"`
	WindowMode string `json:"windowMode,omitempty"`
	BucketNs   int64  `json:"bucketNs,omitempty,string"`
}

type Reference struct {
	Ordinal       uint64 `json:"ordinal"`
	ObservationID string `json:"observationId,omitempty"`
	Sequence      uint64 `json:"snapshotSequence,string"`
}

type Group struct {
	Key                  string      `json:"key"`
	Bytes                int64       `json:"bytes,string"`
	Packets              int64       `json:"packets,string"`
	DurationNs           int64       `json:"durationNs,string"`
	Observations         int         `json:"observations"`
	DistinctPeers        int         `json:"distinctPeers"`
	DistinctPorts        int         `json:"distinctPorts"`
	AverageBitsPerSecond float64     `json:"averageBitsPerSecond"`
	Members              []Reference `json:"members"`
	MembersTruncated     bool        `json:"membersTruncated"`
	BytePercent          float64     `json:"bytePercent"`
	peers                map[string]struct{}
	ports                map[string]struct{}
}

type Result struct {
	Query              Query      `json:"query"`
	ReadRecords        uint64     `json:"readRecords"`
	CollapsedSnapshots uint64     `json:"collapsedSnapshots"`
	Matched            int        `json:"matchedObservations"`
	TotalGroups        int        `json:"totalGroups"`
	Groups             []Group    `json:"groups"`
	Limitations        []string   `json:"limitations"`
	Statistics         Statistics `json:"statistics"`
	Series             []Bucket   `json:"series,omitempty"`
}

type observation struct {
	record *types.Connection
	ref    Reference
}

// Dataset reconciles explicit cumulative snapshots within one analysis dataset.
type Dataset struct {
	limit          int
	records        uint64
	items          []observation
	identities     map[string]int
	legacy         map[string]bool
	explicitTuples map[string]bool
}

func NewDataset(limit int) *Dataset {
	return &Dataset{limit: limit, identities: make(map[string]int), legacy: make(map[string]bool), explicitTuples: make(map[string]bool)}
}

func tuple(c *types.Connection) string {
	a, b := net.JoinHostPort(c.SrcIP, c.SrcPort)+"/"+c.SrcMAC, net.JoinHostPort(c.DstIP, c.DstPort)+"/"+c.DstMAC
	if a > b {
		a, b = b, a
	}
	return c.NetworkProto + "|" + c.TransportProto + "|" + a + "|" + b
}

func (d *Dataset) Add(c *types.Connection, ordinal uint64) error {
	if c == nil || c.TimestampLast < c.TimestampFirst {
		return fmt.Errorf("invalid connection observation at ordinal %d", ordinal)
	}
	d.records++
	ref := Reference{Ordinal: ordinal, ObservationID: c.ObservationID, Sequence: c.SnapshotSequence}
	if c.CounterSemantics == "tuple-cumulative" {
		if d.legacy[tuple(c)] {
			return fmt.Errorf("%w: mixed legacy/cumulative tuple", ErrAmbiguousLegacy)
		}
		d.explicitTuples[tuple(c)] = true
		if c.ObservationID == "" || c.SnapshotSequence == 0 || c.TotalSize64 < 0 || c.NumPackets64 < 0 || c.AppPayloadSize64 < 0 {
			return fmt.Errorf("invalid cumulative counters/identity at ordinal %d", ordinal)
		}
		if index, ok := d.identities[c.ObservationID]; ok {
			previous := d.items[index].record
			if tuple(previous) != tuple(c) {
				return fmt.Errorf("observation identity reused for another tuple at ordinal %d", ordinal)
			}
			if previous.SnapshotSequence == c.SnapshotSequence {
				if !proto.Equal(previous, c) {
					return fmt.Errorf("conflicting snapshot sequence at ordinal %d", ordinal)
				}
				return nil
			}
			older, newer := previous, c
			if c.SnapshotSequence < previous.SnapshotSequence {
				older, newer = c, previous
			}
			if newer.TotalSize64 < older.TotalSize64 || newer.NumPackets64 < older.NumPackets64 || newer.AppPayloadSize64 < older.AppPayloadSize64 ||
				newer.TimestampFirst > older.TimestampFirst || newer.TimestampLast < older.TimestampLast {
				return fmt.Errorf("non-cumulative snapshot at ordinal %d", ordinal)
			}
			if newer == c {
				d.items[index] = observation{record: proto.Clone(c).(*types.Connection), ref: ref}
			}
			return nil
		}
	} else if c.CounterSemantics != "" {
		return fmt.Errorf("unsupported counter semantics %q at ordinal %d", c.CounterSemantics, ordinal)
	} else {
		key := tuple(c)
		if d.legacy[key] || d.explicitTuples[key] {
			return fmt.Errorf("%w: tuple %s", ErrAmbiguousLegacy, key)
		}
		d.legacy[key] = true
	}
	if len(d.items) >= d.limit {
		return fmt.Errorf("flow observation limit exceeded: %d", d.limit)
	}
	if c.CounterSemantics != "" {
		d.identities[c.ObservationID] = len(d.items)
	}
	d.items = append(d.items, observation{record: proto.Clone(c).(*types.Connection), ref: ref})
	return nil
}

func validQuery(q Query) error {
	if q.EndNs < q.StartNs || q.Limit < 1 || q.Limit > 1000 || len(q.Expression) > 4096 {
		return fmt.Errorf("invalid flow time range, result limit or expression length")
	}
	switch q.WindowMode {
	case "", "overlap", "contained", "start", "end":
	default:
		return fmt.Errorf("unsupported time-window mode")
	}
	if q.BucketNs < 0 {
		return fmt.Errorf("bucketNs must be nonnegative")
	}
	if q.BucketNs > 0 && (q.EndNs-q.StartNs <= 0 || (q.EndNs-q.StartNs)/q.BucketNs > 4095) {
		return fmt.Errorf("time series requires a positive window and at most 4096 bins")
	}
	switch q.GroupBy {
	case "srcIP", "dstIP", "dstPort", "pair", "hostPair", "protocol":
	default:
		return fmt.Errorf("unsupported flow groupBy %q", q.GroupBy)
	}
	switch q.SortBy {
	case "bytes", "packets", "records", "peers", "ports", "duration", "rate":
	default:
		return fmt.Errorf("unsupported flow sortBy %q", q.SortBy)
	}
	return nil
}

func (d *Dataset) Query(ctx context.Context, q Query) (Result, error) {
	result := Result{Query: q, ReadRecords: d.records, CollapsedSnapshots: d.records - uint64(len(d.items)), Groups: []Group{}, Limitations: []string{
		"counters cover whole observations overlapping the selected window; they are not clipped to that window",
		"average rate divides total bytes by summed observation durations; it is not peak or time-bin throughput",
		"tuple aggregates are not unique sessions; observation IDs are scoped to this analysis dataset",
		"this query cannot establish packet visibility, sampling, retention or endpoint effects without collection evidence",
	}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := validQuery(q); err != nil {
		return result, err
	}
	program, err := filter.CompileExpression("true", types.Type_NC_Connection)
	if q.Expression != "" {
		program, err = filter.CompileExpression(q.Expression, types.Type_NC_Connection)
	}
	if err != nil {
		return result, err
	}
	groups := make(map[string]*Group)
	var samples []seriesSample
	var totalBytes int64
	for _, item := range d.items {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		c := item.record
		if !matchesWindow(c.TimestampFirst, c.TimestampLast, q) {
			continue
		}
		match, err := filter.EvaluateExpression(program, c)
		if err != nil {
			return result, err
		}
		if !match {
			continue
		}
		bytes, packets := c.TotalSize64, c.NumPackets64
		if c.CounterSemantics == "" {
			if c.TotalSize < 0 || c.NumPackets < 0 {
				return result, fmt.Errorf("legacy counter overflow at ordinal %d", item.ref.Ordinal)
			}
			bytes, packets = int64(c.TotalSize), int64(c.NumPackets)
		}
		key, peer := groupKey(c, q.GroupBy)
		g := groups[key]
		if g == nil {
			if len(groups) >= 10000 {
				return result, fmt.Errorf("flow group limit exceeded: 10000")
			}
			g = &Group{Key: key, Members: []Reference{}, peers: make(map[string]struct{}), ports: make(map[string]struct{})}
			groups[key] = g
		}
		duration := c.TimestampLast - c.TimestampFirst
		if duration < 0 || bytes > math.MaxInt64-g.Bytes || packets > math.MaxInt64-g.Packets || duration > math.MaxInt64-g.DurationNs {
			return result, fmt.Errorf("flow aggregate overflow")
		}
		g.Bytes += bytes
		g.Packets += packets
		g.DurationNs += duration
		g.Observations++
		g.peers[peer] = struct{}{}
		if c.DstPort != "" {
			g.ports[c.TransportProto+"/"+c.DstPort] = struct{}{}
		}
		if bytes > math.MaxInt64-totalBytes {
			return result, fmt.Errorf("total byte count overflow")
		}
		totalBytes += bytes
		samples = append(samples, seriesSample{start: c.TimestampFirst, end: c.TimestampLast, bytes: bytes, packets: packets, client: c.BytesClientToServer, server: c.BytesServerToClient})
		if len(g.Members) < 1000 {
			g.Members = append(g.Members, item.ref)
		} else {
			g.MembersTruncated = true
		}
		result.Matched++
	}
	for _, g := range groups {
		if totalBytes > 0 {
			g.BytePercent = 100 * float64(g.Bytes) / float64(totalBytes)
		}
		g.DistinctPeers = len(g.peers)
		g.DistinctPorts = len(g.ports)
		if g.DurationNs > 0 {
			g.AverageBitsPerSecond = float64(g.Bytes) * 8e9 / float64(g.DurationNs)
		}
		result.Groups = append(result.Groups, *g)
	}
	result.Statistics = sampleStatistics(samples)
	if q.BucketNs > 0 {
		result.Series, err = sampleSeries(ctx, samples, q)
		if err != nil {
			return result, err
		}
		result.Limitations = append(result.Limitations, "time-series bytes and rates are uniform-over-duration estimates, not observed packet bins; zero-duration observations are assigned to their timestamp")
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		a, b := result.Groups[i], result.Groups[j]
		switch q.SortBy {
		case "bytes":
			if a.Bytes != b.Bytes {
				return a.Bytes > b.Bytes
			}
		case "packets":
			if a.Packets != b.Packets {
				return a.Packets > b.Packets
			}
		case "records":
			if a.Observations != b.Observations {
				return a.Observations > b.Observations
			}
		case "ports":
			if a.DistinctPorts != b.DistinctPorts {
				return a.DistinctPorts > b.DistinctPorts
			}
		case "peers":
			if a.DistinctPeers != b.DistinctPeers {
				return a.DistinctPeers > b.DistinctPeers
			}
		case "duration":
			if a.DurationNs != b.DurationNs {
				return a.DurationNs > b.DurationNs
			}
		case "rate":
			if a.AverageBitsPerSecond != b.AverageBitsPerSecond {
				return a.AverageBitsPerSecond > b.AverageBitsPerSecond
			}
		}
		return a.Key < b.Key
	})
	result.TotalGroups = len(result.Groups)
	if len(result.Groups) > q.Limit {
		result.Groups = result.Groups[:q.Limit]
	}
	return result, nil
}

func groupKey(c *types.Connection, group string) (string, string) {
	switch group {
	case "srcIP":
		return c.SrcIP, c.DstIP
	case "dstIP":
		return c.DstIP, c.SrcIP
	case "dstPort":
		return c.TransportProto + "/" + c.DstPort, c.DstIP
	case "protocol":
		return c.TransportProto, c.DstIP
	case "hostPair":
		return c.SrcIP + "/" + c.DstIP, c.DstIP
	default:
		return c.TransportProto + "/" + net.JoinHostPort(c.SrcIP, c.SrcPort) + "/" + net.JoinHostPort(c.DstIP, c.DstPort), c.DstIP
	}
}

func ParseQuery(values map[string][]string) (Query, error) {
	for _, key := range []string{"startNs", "endNs", "filter", "groupBy", "sortBy", "limit", "windowMode", "bucketNs"} {
		if len(values[key]) > 1 {
			return Query{}, fmt.Errorf("duplicate flow query parameter %s", key)
		}
	}
	get := func(key string) string {
		if v := values[key]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	start, err := strconv.ParseInt(get("startNs"), 10, 64)
	if err != nil {
		return Query{}, fmt.Errorf("startNs must be an exact nanosecond integer")
	}
	end, err := strconv.ParseInt(get("endNs"), 10, 64)
	if err != nil {
		return Query{}, fmt.Errorf("endNs must be an exact nanosecond integer")
	}
	q := Query{StartNs: start, EndNs: end, Expression: get("filter"), GroupBy: get("groupBy"), SortBy: get("sortBy"), Limit: 100}
	q.WindowMode = get("windowMode")
	if raw := get("bucketNs"); raw != "" {
		q.BucketNs, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return q, fmt.Errorf("invalid bucketNs")
		}
	}
	if q.GroupBy == "" {
		q.GroupBy = "srcIP"
	}
	if q.SortBy == "" {
		q.SortBy = "bytes"
	}
	if raw := get("limit"); raw != "" {
		q.Limit, err = strconv.Atoi(raw)
		if err != nil {
			return q, err
		}
	}
	return q, validQuery(q)
}
