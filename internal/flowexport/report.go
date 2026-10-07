package flowexport

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

type Query struct {
	StartNs   int64   `json:"startNs,string"`
	EndNs     int64   `json:"endNs,string"`
	TimeBasis string  `json:"timeBasis"`
	Exporter  string  `json:"exporter"`
	Format    string  `json:"format"`
	Domain    *uint32 `json:"domain,omitempty"`
	Host      string  `json:"host,omitempty"`
	GroupBy   string  `json:"groupBy"`
	Limit     int     `json:"limit"`
}

type Group struct {
	Key              string   `json:"key"`
	Bytes            uint64   `json:"bytes,string"`
	Packets          uint64   `json:"packets,string"`
	Records          int      `json:"records"`
	Peers            int      `json:"peers"`
	Members          []string `json:"observationIds"`
	MembersTruncated bool     `json:"membersTruncated"`
	peers            map[string]bool
}

type Report struct {
	Version      int            `json:"version"`
	Query        Query          `json:"query"`
	SourceSHA256 string         `json:"sourceSHA256"`
	Health       RecorderHealth `json:"health"`
	Groups       []Group        `json:"groups"`
	TotalGroups  int            `json:"totalGroups"`
	Matched      int            `json:"matchedRecords"`
	Excluded     int            `json:"unquantifiableRecords"`
	Limitations  []string       `json:"limitations"`
}

func ReadReport(ctx context.Context, path string, query Query) (Report, error) {
	result := Report{Version: 1, Query: query, Groups: []Group{}, Limitations: []string{"counts are exporter-reported; no sampling scaling is inferred", "whole observations overlap the chosen window; counters are not clipped", "cumulative export counters and records lacking bytes/packets are excluded from additive rankings", "one exporter/domain scope is required; observations are not unique sessions"}}
	if query.Exporter == "" || query.Format == "" || query.Domain == nil || query.EndNs < query.StartNs || query.Limit < 1 || query.Limit > 1000 {
		return result, fmt.Errorf("bounded exporter/format/domain/time scope and limit 1..1000 required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := netip.ParseAddrPort(query.Exporter); err != nil {
		return result, fmt.Errorf("invalid exporter: %w", err)
	}
	switch query.Format {
	case "netflow-v5", "netflow-v9", "ipfix", "sflow-v5":
	default:
		return result, fmt.Errorf("unsupported export format")
	}
	if query.TimeBasis != "flow" && query.TimeBasis != "receive" {
		return result, fmt.Errorf("time basis must be flow or receive")
	}
	switch query.GroupBy {
	case "srcIP", "dstIP", "dstPort", "protocol", "ingress", "egress", "srcAS", "dstAS", "nextHop":
	default:
		return result, fmt.Errorf("unsupported export group %q", query.GroupBy)
	}
	var prefix netip.Prefix
	if query.Host != "" {
		var err error
		prefix, err = netip.ParsePrefix(query.Host)
		if err != nil {
			addr, aerr := netip.ParseAddr(query.Host)
			if aerr != nil {
				return result, err
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
	}
	healthData, err := os.ReadFile(filepath.Join(filepath.Dir(path), "FlowExportsHealth.json"))
	if err != nil {
		return result, fmt.Errorf("export collection health unavailable: %w", err)
	}
	if err := json.Unmarshal(healthData, &result.Health); err != nil {
		return result, err
	}
	if result.Health.Status != "done" && result.Health.Status != "partial" {
		return result, fmt.Errorf("export collection is %s, not a finalized dataset", result.Health.Status)
	}
	if result.Health.Status == "partial" {
		result.Limitations = append(result.Limitations, "collection is partial: inspect health and issue events before interpreting a negative search")
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return result, err
	}
	digest := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, digest))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	groups := map[string]*Group{}
	seen := map[string]bool{}
	records := 0
	collector := ""
	samplingKey := ""
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		records++
		if records > 1000000 {
			return result, fmt.Errorf("export input event limit exceeded")
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return result, err
		}
		if event.Kind == "issue" || event.Kind == "datagram" {
			continue
		}
		if event.Kind != "observation" || event.Observation == nil {
			return result, fmt.Errorf("invalid export event")
		}
		o := event.Observation
		if o.Envelope.Exporter != query.Exporter || o.Format != query.Format || o.Domain != *query.Domain {
			continue
		}
		if collector != "" && collector != o.Envelope.Collector {
			return result, fmt.Errorf("multiple collector transport scopes in selected dataset")
		}
		collector = o.Envelope.Collector
		if o.ID == "" || seen[o.ID] {
			return result, fmt.Errorf("missing or duplicate export observation identity")
		}
		seen[o.ID] = true
		if query.TimeBasis == "receive" {
			if o.Envelope.ReceivedNs < query.StartNs || o.Envelope.ReceivedNs > query.EndNs {
				continue
			}
		} else {
			if o.StartNs == nil || o.EndNs == nil {
				result.Excluded++
				continue
			}
			if *o.StartNs > query.EndNs || *o.EndNs < query.StartNs {
				continue
			}
		}
		if prefix.IsValid() {
			src, _ := netip.ParseAddr(o.SrcIP)
			dst, _ := netip.ParseAddr(o.DstIP)
			if !prefix.Contains(src) && !prefix.Contains(dst) {
				continue
			}
		}
		if o.Bytes == nil || o.Packets == nil || o.CounterSemantics == "exported-cumulative-as-reported" {
			result.Excluded++
			continue
		}
		if o.CounterSemantics != "exported-delta-as-reported" && o.CounterSemantics != "sampled-packet-as-reported" {
			return result, fmt.Errorf("unknown export counter semantics")
		}
		currentSampling := fmt.Sprintf("%s/%d/%d", o.Sampling.Status, o.Sampling.Interval, o.Sampling.Algorithm)
		if samplingKey != "" && currentSampling != samplingKey {
			return result, fmt.Errorf("incompatible sampling metadata in selected observations; narrow the time window")
		}
		samplingKey = currentSampling
		key, peer := exportGroup(o, query.GroupBy)
		g := groups[key]
		if g == nil {
			if len(groups) >= 10000 {
				return result, fmt.Errorf("export group limit exceeded")
			}
			g = &Group{Key: key, Members: []string{}, peers: map[string]bool{}}
			groups[key] = g
		}
		if *o.Bytes > math.MaxUint64-g.Bytes || *o.Packets > math.MaxUint64-g.Packets {
			return result, fmt.Errorf("export aggregate overflow")
		}
		g.Bytes += *o.Bytes
		g.Packets += *o.Packets
		g.Records++
		g.peers[peer] = true
		if len(g.Members) < 1000 {
			g.Members = append(g.Members, o.ID)
		} else {
			g.MembersTruncated = true
		}
		result.Matched++
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	after, err := file.Stat()
	if err != nil {
		return result, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return result, fmt.Errorf("export dataset changed during query")
	}
	for _, g := range groups {
		g.Peers = len(g.peers)
		result.Groups = append(result.Groups, *g)
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		a, b := result.Groups[i], result.Groups[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.Key < b.Key
	})
	result.TotalGroups = len(result.Groups)
	if len(result.Groups) > query.Limit {
		result.Groups = result.Groups[:query.Limit]
	}
	result.SourceSHA256 = hex.EncodeToString(digest.Sum(nil))
	if result.SourceSHA256 != result.Health.RecordsSHA256 {
		return result, fmt.Errorf("export collection health does not match record-file hash")
	}
	return result, ctx.Err()
}

func exportGroup(o *Observation, group string) (string, string) {
	value := func(n *uint64) string {
		if n == nil {
			return "unavailable"
		}
		return fmt.Sprint(*n)
	}
	switch group {
	case "srcIP":
		return o.SrcIP, o.DstIP
	case "dstIP":
		return o.DstIP, o.SrcIP
	case "dstPort":
		return value(o.Protocol) + "/" + value(o.DstPort), o.DstIP
	case "protocol":
		return value(o.Protocol), o.DstIP
	case "ingress":
		return value(o.Ingress), o.SrcIP
	case "egress":
		return value(o.Egress), o.DstIP
	case "srcAS":
		return value(o.SrcAS), o.DstIP
	case "dstAS":
		return value(o.DstAS), o.SrcIP
	default:
		return o.NextHop, o.DstIP
	}
}
