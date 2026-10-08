/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

// Package evidencelink links audit records across protocols: records of one
// connection (Community ID within the connection's time span), the DNS answer
// that resolved a connection's destination, connections opened to resolved
// addresses, and alerts raised on any of them.
//
// Links are computed from an output directory at query time. The result does
// not depend on worker count or record emission order, only on record content.
package evidencelink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// Schema is the version of the Result JSON contract.
const Schema = 1

// IndexBudget bounds accounted storage for records, summaries and join keys.
const IndexBudget uint64 = 64 << 20

// Link kinds.
const (
	KindSameConnection     = "same-connection"
	KindSameFlow           = "same-flow"
	KindAlert              = "alert"
	KindDNSResolution      = "dns-resolution"
	KindResolvedConnection = "resolved-connection"
)

// Link bases: how a link was established.
const (
	BasisCommunityIDSpan   = "community-id-in-connection-span"
	BasisCommunityIDWindow = "community-id-within-window"
	BasisAnswerBefore      = "dns-answer-before-connection"
	BasisConnectionAfter   = "connection-after-dns-answer"
)

// Config bounds index construction and query results.
type Config struct {
	Enabled    bool  `json:"enabled"`
	WindowNS   int64 `json:"windowNs"`
	MaxRecords int64 `json:"maxRecords"`
	MaxLinks   int   `json:"maxLinks"`
}

// DefaultConfig: one hour join window, 1,000,000 indexed records, 500 links.
func DefaultConfig() Config {
	return Config{Enabled: true, WindowNS: 3600e9, MaxRecords: 1_000_000, MaxLinks: 500}
}

// Validate rejects unbounded or nonsensical limits.
func (c Config) Validate() error {
	switch {
	case c.WindowNS <= 0 || c.WindowNS > 7*24*3600e9:
		return errors.New("evidence links window must be within (0, 7d]")
	case c.MaxRecords <= 0 || c.MaxRecords > 50_000_000:
		return errors.New("evidence links max records must be within [1, 50000000]")
	case c.MaxLinks <= 0 || c.MaxLinks > 10_000:
		return errors.New("evidence links max links must be within [1, 10000]")
	}
	return nil
}

// Field is one summary value, rendered as text.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Record identifies an audit record by file type and position.
type Record struct {
	Type        string  `json:"type"`
	Ordinal     int64   `json:"ordinal"`
	Timestamp   int64   `json:"timestamp"`
	CommunityID string  `json:"communityId,omitempty"`
	Summary     []Field `json:"summary,omitempty"`
}

// Link is one related record and how it was found.
type Link struct {
	Kind   string `json:"kind"`
	Basis  string `json:"basis"`
	Record Record `json:"record"`
}

// Session is the connection observation that scopes Community ID links.
type Session struct {
	ObservationID string `json:"observationId,omitempty"`
	CommunityID   string `json:"communityId"`
	First         int64  `json:"first"`
	Last          int64  `json:"last"`
	SrcIP         string `json:"srcIp"`
	SrcPort       string `json:"srcPort"`
	DstIP         string `json:"dstIp"`
	DstPort       string `json:"dstPort"`
	Ordinal       int64  `json:"ordinal"`
	snapshot      uint64
}

// Result is the API and CLI response.
type Result struct {
	Schema    int      `json:"schema"`
	Target    Record   `json:"target"`
	Session   *Session `json:"session"`
	Links     []Link   `json:"links"`
	Truncated bool     `json:"truncated"`
	Indexed   int64    `json:"indexed"`
	Limits    Config   `json:"limits"`
	Notes     []string `json:"notes"`
}

type dnsAnswer struct {
	client string
	record Record
}

// Index holds the joinable records of one output directory.
type Index struct {
	config   Config
	byRef    map[string]Record
	byCID    map[string][]Record
	sessions map[string][]*Session // by Community ID
	byObs    map[string]*Session
	conns    map[string][]*Session // by client|server
	answers  map[string][]dnsAnswer
	dnsIPs   map[string][]string // DNS response ref -> answered IPs
	dnsPeer  map[string]string   // DNS response ref -> client
	indexed  int64
	full     bool
	bytes    uint64
}

func refKey(typ string, ordinal int64) string { return typ + "#" + strconv.FormatInt(ordinal, 10) }

// Joinable reports whether a Community ID is a computed v1 value; fallback
// identifiers (connection hashes without a Community ID) never join.
func Joinable(id string) bool { return strings.HasPrefix(id, "1:") }

// Build indexes every audit file in dir, in file-name order.
func Build(dir string, config Config) (*Index, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if info, err := os.Stat(dir); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, errors.New("evidence linking requires an output directory")
	}
	idx := &Index{
		config: config, byRef: map[string]Record{}, byCID: map[string][]Record{},
		sessions: map[string][]*Session{}, byObs: map[string]*Session{}, conns: map[string][]*Session{},
		answers: map[string][]dnsAnswer{}, dnsIPs: map[string][]string{}, dnsPeer: map[string]string{},
	}
	for _, file := range auditFiles(dir) {
		if idx.full {
			break
		}
		if err := idx.addFile(file.typ, file.path); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(file.path), err)
		}
	}
	for _, list := range idx.byCID {
		sort.Slice(list, func(i, j int) bool { return less(list[i], list[j]) })
	}
	return idx, nil
}

// PacketTypes are per-packet records; linking them would list every packet of
// a connection, so they are not indexed.
var PacketTypes = map[string]bool{"TCP": true, "TLSRecord": true, "PacketContext": true, "PKTAP": true}

type auditFile struct{ typ, path string }

func auditFiles(dir string) []auditFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var files []auditFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		typ := ""
		switch {
		case strings.HasSuffix(name, defaults.FileExtension+".gz"):
			typ = strings.TrimSuffix(name, defaults.FileExtension+".gz")
		case strings.HasSuffix(name, defaults.FileExtension):
			typ = strings.TrimSuffix(name, defaults.FileExtension)
		}
		if typ == "" || seen[typ] || PacketTypes[typ] || strings.ContainsAny(typ, `/\.`) {
			continue
		}
		seen[typ] = true
		files = append(files, auditFile{typ: typ, path: filepath.Join(dir, name)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].typ < files[j].typ })
	return files
}

func (idx *Index) addFile(typ, path string) error {
	reader, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		return err
	}
	defer reader.Close()
	header, err := reader.ReadHeader()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	message := netio.InitRecord(header.Type)
	if message == nil {
		return nil
	}
	field, hasID := reflect.TypeOf(message).Elem().FieldByName("CommunityID")
	hasID = hasID && field.Type.Kind() == reflect.String
	isAlert := header.Type == types.Type_NC_Alert
	if !hasID && !isAlert {
		return nil
	}
	for ordinal := int64(0); ; ordinal++ {
		if err := reader.Next(message); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if idx.indexed >= idx.config.MaxRecords {
			idx.full = true
			return nil
		}
		record, ok := message.(types.AuditRecord)
		if !ok {
			return nil
		}
		cid := ""
		if hasID {
			cid = reflect.ValueOf(message).Elem().FieldByIndex(field.Index).String()
		}
		if alert, ok := message.(*types.Alert); ok {
			cid = matchedCommunityID(alert.MatchedRecord)
		}
		if !Joinable(cid) {
			continue
		}
		entry := Record{Type: typ, Ordinal: ordinal, Timestamp: record.Time(), CommunityID: cid, Summary: Summarize(typ, message)}
		cost := storageCost(entry, message)
		if cost > IndexBudget-idx.bytes {
			idx.full = true
			return nil
		}
		idx.bytes += cost
		idx.indexed++
		key := refKey(typ, ordinal)
		idx.byRef[key] = entry
		idx.byCID[cid] = append(idx.byCID[cid], entry)
		switch value := message.(type) {
		case *types.Connection:
			idx.addConnection(value, entry)
		case *types.DNS:
			idx.addDNS(value, entry, key)
		}
	}
}

func storageCost(entry Record, message any) uint64 {
	cost := uint64(1024 + 4*(len(entry.Type)+len(entry.CommunityID)))
	for _, field := range entry.Summary {
		cost += uint64(4 * (len(field.Name) + len(field.Value)))
	}
	switch value := message.(type) {
	case *types.Connection:
		cost += uint64(4 * (len(value.ObservationID) + len(value.SrcIP) + len(value.DstIP) + len(value.SrcPort) + len(value.DstPort)))
	case *types.DNS:
		for _, answer := range value.Answers {
			if answer != nil && (answer.Type == 1 || answer.Type == 28) {
				cost += uint64(512 + 4*(len(value.DstIP)+len(answer.IP)))
			}
		}
	}
	return cost
}

func (idx *Index) addConnection(c *types.Connection, entry Record) {
	last := c.TimestampLast
	if last < c.TimestampFirst {
		last = c.TimestampFirst
	}
	session := &Session{
		ObservationID: c.ObservationID, CommunityID: entry.CommunityID, First: c.TimestampFirst, Last: last,
		SrcIP: c.SrcIP, SrcPort: c.SrcPort, DstIP: c.DstIP, DstPort: c.DstPort, Ordinal: entry.Ordinal, snapshot: c.SnapshotSequence,
	}
	if c.ObservationID != "" {
		if prior := idx.byObs[c.ObservationID]; prior != nil {
			// Keep the latest cumulative snapshot of one observation.
			if c.SnapshotSequence > prior.snapshot || (c.SnapshotSequence == prior.snapshot && entry.Ordinal < prior.Ordinal) {
				*prior = *session
			}
			return
		}
		idx.byObs[c.ObservationID] = session
	}
	idx.sessions[entry.CommunityID] = append(idx.sessions[entry.CommunityID], session)
	key := c.SrcIP + "|" + c.DstIP
	idx.conns[key] = append(idx.conns[key], session)
}

func (idx *Index) addDNS(d *types.DNS, entry Record, key string) {
	if !d.QR {
		return
	}
	var ips []string
	for _, answer := range d.Answers {
		if answer == nil || (answer.Type != 1 && answer.Type != 28) {
			continue
		}
		addr, err := netip.ParseAddr(answer.IP)
		if err != nil {
			continue
		}
		ip := addr.Unmap().String()
		ips = append(ips, ip)
		idx.answers[ip] = append(idx.answers[ip], dnsAnswer{client: d.DstIP, record: entry})
	}
	if len(ips) > 0 {
		idx.dnsIPs[key] = ips
		idx.dnsPeer[key] = d.DstIP
	}
}

func matchedCommunityID(matched string) string {
	if matched == "" {
		return ""
	}
	var fields struct {
		CommunityID string `json:"CommunityID"`
	}
	if json.Unmarshal([]byte(matched), &fields) != nil {
		return ""
	}
	return fields.CommunityID
}

func less(a, b Record) bool {
	if a.Timestamp != b.Timestamp {
		return a.Timestamp < b.Timestamp
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return a.Ordinal < b.Ordinal
}

// ErrNotFound reports a reference that is not an indexed, joinable record.
var ErrNotFound = errors.New("record is not indexed: missing, beyond limits or without a Community ID")

// Selector identifies the target record: Type+Ordinal, ObservationID (the
// latest snapshot of a Connection observation), or Type+CommunityID+Time
// (exactly one record of that type with that timestamp; ambiguous matches fail).
type Selector struct {
	Type          string
	Ordinal       int64
	HasOrdinal    bool
	ObservationID string
	CommunityID   string
	Time          int64
	HasTime       bool
}

// Resolve returns the type and ordinal of the selected record.
func (idx *Index) Resolve(sel Selector) (string, int64, error) {
	switch {
	case sel.ObservationID != "":
		if s := idx.byObs[sel.ObservationID]; s != nil {
			return "Connection", s.Ordinal, nil
		}
	case sel.Type != "" && sel.HasOrdinal:
		if _, ok := idx.byRef[refKey(sel.Type, sel.Ordinal)]; ok {
			return sel.Type, sel.Ordinal, nil
		}
	case sel.Type != "" && sel.CommunityID != "" && sel.HasTime:
		found := false
		var best int64
		for _, r := range idx.byCID[sel.CommunityID] {
			if r.Type == sel.Type && r.Timestamp == sel.Time {
				if found {
					return "", 0, errors.New("ambiguous record selection; use type and ordinal")
				}
				best, found = r.Ordinal, true
			}
		}
		if found {
			return sel.Type, best, nil
		}
	default:
		return "", 0, errors.New("select a record by type and ordinal, observationId, or type, communityId and time")
	}
	return "", 0, ErrNotFound
}

// Related returns the records linked to type/ordinal.
func (idx *Index) Related(typ string, ordinal int64) (*Result, error) {
	key := refKey(typ, ordinal)
	target, ok := idx.byRef[key]
	if !ok {
		return nil, ErrNotFound
	}
	result := &Result{Schema: Schema, Target: target, Links: []Link{}, Indexed: idx.indexed, Limits: idx.config, Truncated: idx.full, Notes: []string{}}
	if idx.full {
		result.Notes = append(result.Notes, "index reached its record limit or 64 MiB accounted storage budget; later records are not linked")
	}
	session := idx.session(target)
	result.Session = session
	seen := map[string]bool{key: true}
	add := func(kind, basis string, record Record) {
		k := refKey(record.Type, record.Ordinal)
		if seen[k] {
			return
		}
		seen[k] = true
		result.Links = append(result.Links, Link{Kind: kind, Basis: basis, Record: record})
	}
	members := idx.byCID[target.CommunityID]
	if session != nil {
		for _, record := range members {
			if record.Timestamp < session.First || record.Timestamp > session.Last {
				continue
			}
			if record.Type == "Connection" && !idx.sameObservation(record, session) {
				continue
			}
			kind := KindSameConnection
			if record.Type == "Alert" {
				kind = KindAlert
			}
			add(kind, BasisCommunityIDSpan, record)
		}
		if answer, ok := idx.resolution(session); ok {
			add(KindDNSResolution, BasisAnswerBefore, answer)
		}
	} else if len(idx.sessions[target.CommunityID]) > 0 {
		result.Notes = append(result.Notes, "no unique Connection observation contains this record; same-flow links are withheld")
	} else {
		result.Notes = append(result.Notes, "no Connection observation contains this record; Community ID links use the time window")
		for _, record := range members {
			if !within(record.Timestamp, target.Timestamp, idx.config.WindowNS) {
				continue
			}
			kind := KindSameFlow
			if record.Type == "Alert" {
				kind = KindAlert
			}
			add(kind, BasisCommunityIDWindow, record)
		}
	}
	if ips := idx.dnsIPs[key]; len(ips) > 0 {
		client := idx.dnsPeer[key]
		for _, ip := range ips {
			for _, candidate := range idx.conns[client+"|"+ip] {
				if candidate.First < target.Timestamp || !within(candidate.First, target.Timestamp, idx.config.WindowNS) {
					continue
				}
				if record, ok := idx.byRef[refKey("Connection", candidate.Ordinal)]; ok {
					add(KindResolvedConnection, BasisConnectionAfter, record)
				}
			}
		}
	}
	sort.SliceStable(result.Links, func(i, j int) bool { return less(result.Links[i].Record, result.Links[j].Record) })
	if len(result.Links) > idx.config.MaxLinks {
		result.Links = result.Links[:idx.config.MaxLinks]
		result.Truncated = true
		result.Notes = append(result.Notes, fmt.Sprintf("only the first %d links are returned", idx.config.MaxLinks))
	}
	return result, nil
}

func (idx *Index) sameObservation(record Record, session *Session) bool {
	if session.ObservationID == "" {
		return record.Ordinal == session.Ordinal
	}
	for _, s := range idx.sessions[session.CommunityID] {
		if s.Ordinal == record.Ordinal {
			return s == session
		}
	}
	return false
}

// session selects the connection observation that contains the target.
func (idx *Index) session(target Record) *Session {
	candidates := idx.sessions[target.CommunityID]
	if target.Type == "Connection" {
		for _, s := range candidates {
			if s.Ordinal == target.Ordinal {
				return s
			}
		}
		// An earlier snapshot of an observation resolves to its latest one.
		for _, s := range candidates {
			if s.First == target.Timestamp {
				return s
			}
		}
	}
	var best *Session
	for _, s := range candidates {
		if target.Timestamp < s.First || target.Timestamp > s.Last {
			continue
		}
		if best != nil {
			return nil
		}
		best = s
	}
	return best
}

func (idx *Index) resolution(session *Session) (Record, bool) {
	addr, err := netip.ParseAddr(session.DstIP)
	if err != nil {
		return Record{}, false
	}
	var best *Record
	for _, answer := range idx.answers[addr.Unmap().String()] {
		r := answer.record
		if answer.client != session.SrcIP || r.Timestamp > session.First || !within(session.First, r.Timestamp, idx.config.WindowNS) {
			continue
		}
		if best == nil || r.Timestamp > best.Timestamp || (r.Timestamp == best.Timestamp && r.Ordinal < best.Ordinal) {
			copy := r
			best = &copy
		}
	}
	if best == nil {
		return Record{}, false
	}
	return *best, true
}

// Unsigned subtraction avoids overflow for adversarial int64 timestamps.
func within(a, b, window int64) bool {
	if a < b {
		a, b = b, a
	}
	return uint64(a)-uint64(b) <= uint64(window)
}
