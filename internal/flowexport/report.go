package flowexport

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"path/filepath"
	"sort"

	"github.com/dreadl0ck/netcap/internal/artifactio"
)

const (
	maxReportHealthBytes  = 1 << 20
	maxReportRecordsBytes = 256 << 20
	maxReportIndexBytes   = 128 << 20
	maxReportOutputBytes  = 16 << 20
)

// ErrReportLimit indicates that a flow export query exceeds its resource budget.
var ErrReportLimit = errors.New("export report limit exceeded")

type Query struct {
	StartNs   int64   `json:"startNs,string"`
	EndNs     int64   `json:"endNs,string"`
	TimeBasis string  `json:"timeBasis"`
	Exporter  string  `json:"exporter"`
	Format    string  `json:"format"`
	Domain    *uint32 `json:"domain,omitempty"`
	Host      string  `json:"host,omitempty"`
	Ingress   *uint64 `json:"ingress,omitempty,string"`
	Egress    *uint64 `json:"egress,omitempty,string"`
	NextHop   string  `json:"nextHop,omitempty"`
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
	return readReport(ctx, path, query, maxReportIndexBytes)
}

func readReport(ctx context.Context, path string, query Query, indexBudget int) (Report, error) {
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
	case "srcIP", "dstIP", "dstPort", "protocol", "ingress", "egress", "ingressEgress", "srcAS", "dstAS", "nextHop", "srcPrefix", "dstPrefix":
	default:
		return result, fmt.Errorf("unsupported export group %q", query.GroupBy)
	}
	var prefix netip.Prefix
	if query.NextHop != "" {
		if _, err := netip.ParseAddr(query.NextHop); err != nil {
			return result, fmt.Errorf("invalid next hop: %w", err)
		}
	}
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
	dir := filepath.Dir(path)
	healthData, err := artifactio.Read(ctx, dir, "FlowExportsHealth.json", maxReportHealthBytes)
	if err != nil {
		if errors.Is(err, artifactio.ErrSizeLimit) {
			return result, fmt.Errorf("export collection health unavailable: %w: %w", err, ErrReportLimit)
		}
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
	file, before, err := artifactio.Open(dir, filepath.Base(path))
	if err != nil {
		return result, err
	}
	defer file.Close()
	if before.Size() > maxReportRecordsBytes {
		return result, fmt.Errorf("export record file exceeds %d byte limit: %w", maxReportRecordsBytes, ErrReportLimit)
	}
	digest := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(io.NewSectionReader(file, 0, before.Size()), digest))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	groups := map[string]*Group{}
	seen := map[string]bool{}
	charge := func(bytes int) bool {
		if bytes > indexBudget {
			return false
		}
		indexBudget -= bytes
		return true
	}
	indexLimitErr := fmt.Errorf("export query index budget exceeded; narrow the query scope: %w", ErrReportLimit)
	records := 0
	collector := ""
	samplingKey := ""
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		records++
		if records > 1000000 {
			return result, fmt.Errorf("export input event limit exceeded: %w", ErrReportLimit)
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
		if !charge(48 + len(o.ID)) {
			return result, indexLimitErr
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
		if query.Ingress != nil && (o.Ingress == nil || *o.Ingress != *query.Ingress) ||
			query.Egress != nil && (o.Egress == nil || *o.Egress != *query.Egress) ||
			query.NextHop != "" && o.NextHop != query.NextHop {
			continue
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
				return result, fmt.Errorf("export group limit exceeded: %w", ErrReportLimit)
			}
			if !charge(192 + len(key)) {
				return result, indexLimitErr
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
		if !g.peers[peer] {
			if !charge(48 + len(peer)) {
				return result, indexLimitErr
			}
			g.peers[peer] = true
		}
		if len(g.Members) < 1000 {
			if !charge(32) {
				return result, indexLimitErr
			}
			g.Members = append(g.Members, o.ID)
		} else {
			g.MembersTruncated = true
		}
		result.Matched++
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
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
	if err := checkReportOutputSize(ctx, result, maxReportOutputBytes); err != nil {
		result.Groups = []Group{}
		return result, err
	}
	return result, ctx.Err()
}

func checkReportOutputSize(ctx context.Context, report Report, limit int) error {
	groups := report.Groups
	if groups != nil {
		report.Groups = []Group{}
	}
	header, err := json.Marshal(report)
	if err != nil {
		return err
	}
	remaining := limit - len(header) - 1 // The HTTP encoder adds a newline.
	tooLarge := fmt.Errorf("export report exceeds %d encoded bytes; narrow the query or lower the group limit: %w", limit, ErrReportLimit)
	if remaining < 0 {
		return tooLarge
	}
	for i, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		members := group.Members
		if members != nil {
			group.Members = []string{}
		}
		raw, err := json.Marshal(group)
		if err != nil {
			return err
		}
		remaining -= len(raw)
		if i > 0 {
			remaining--
		}
		if remaining < 0 {
			return tooLarge
		}
		for j, member := range members {
			if len(member)+2 > remaining {
				return tooLarge
			}
			encoded, err := json.Marshal(member)
			if err != nil {
				return err
			}
			remaining -= len(encoded)
			if j > 0 {
				remaining--
			}
			if remaining < 0 {
				return tooLarge
			}
		}
	}
	return nil
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
	case "ingressEgress":
		return value(o.Ingress) + "/" + value(o.Egress), o.DstIP
	case "srcAS":
		return value(o.SrcAS), o.DstIP
	case "dstAS":
		return value(o.DstAS), o.SrcIP
	case "srcPrefix":
		return exportedPrefix(o.SrcIP, o.SrcPrefixLength), o.DstIP
	case "dstPrefix":
		return exportedPrefix(o.DstIP, o.DstPrefixLength), o.SrcIP
	default:
		if o.NextHop == "" {
			return "unavailable", o.DstIP
		}
		return o.NextHop, o.DstIP
	}
}

func exportedPrefix(ip string, length *uint64) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || length == nil || *length > uint64(addr.BitLen()) {
		return "unavailable"
	}
	return netip.PrefixFrom(addr, int(*length)).Masked().String()
}
