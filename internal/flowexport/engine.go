package flowexport

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
)

type fieldSpec struct {
	id, length                uint16
	enterprise                uint32
	enterpriseProvided, scope bool
}
type template struct {
	fields  []fieldSpec
	options bool
	seen    int64
}
type scope struct {
	exporter, collector string
	version             uint16
	domain              uint32
}
type domainState struct {
	templates                             map[uint16]template
	sequence, expected, uptime            uint32
	hasSequence, expectedKnown, hasUptime bool
	seen                                  int64
	sampling                              Sampling
	active, idle                          *uint64
	lastDigest                            [32]byte
}

type Engine struct {
	mu      sync.Mutex
	config  Config
	domains map[scope]*domainState
	health  Health
}

func New(config Config) (*Engine, error) {
	if config.TemplateTTL <= 0 || config.MaxDomains < 1 || config.MaxTemplates < 1 || config.MaxFields < 1 {
		return nil, fmt.Errorf("invalid flow-export limits")
	}
	return &Engine{config: config, domains: make(map[scope]*domainState), health: Health{Version: 1, Limitations: []string{
		"exported observations are metadata, not reconstructed sessions or payload evidence",
		"sampling counts are retained verbatim; no automatic scaling or cross-exporter deduplication",
		"sequence discontinuities may be loss, restart or reordering; silence does not establish coverage",
	}}}, nil
}

func (e *Engine) Health() Health {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.health
	h.Limitations = append([]string(nil), h.Limitations...)
	return h
}

func (e *Engine) Decode(data []byte, envelope Envelope) (Batch, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	batch := Batch{Observations: []Observation{}, Issues: []Issue{}}
	e.health.Datagrams++
	if _, err := netip.ParseAddrPort(envelope.Exporter); err != nil {
		return batch, fmt.Errorf("invalid exporter identity: %w", err)
	}
	if _, err := netip.ParseAddrPort(envelope.Collector); err != nil {
		return batch, fmt.Errorf("invalid collector identity: %w", err)
	}
	if len(data) < 2 || len(data) > 65535 {
		e.health.Malformed++
		return batch, fmt.Errorf("invalid export datagram length: %d", len(data))
	}
	version := binary.BigEndian.Uint16(data)
	var domain, seq, uptime uint32
	var exportNs int64
	var header int
	switch version {
	case 5:
		if len(data) < 24 {
			e.health.Malformed++
			return batch, fmt.Errorf("truncated NetFlow v5 header")
		}
		header = 24
		uptime = u32(data[4:])
		exportNs = int64(u32(data[8:]))*1e9 + int64(u32(data[12:]))
		seq = u32(data[16:])
		domain = uint32(data[20])<<8 | uint32(data[21])
		if u32(data[12:]) >= 1e9 {
			e.health.Malformed++
			return batch, fmt.Errorf("invalid NetFlow v5 nanoseconds")
		}
	case 9:
		if len(data) < 20 {
			e.health.Malformed++
			return batch, fmt.Errorf("truncated NetFlow v9 header")
		}
		header = 20
		uptime = u32(data[4:])
		exportNs = int64(u32(data[8:])) * 1e9
		seq = u32(data[12:])
		domain = u32(data[16:])
	case 10:
		if len(data) < 16 || int(u16(data[2:])) != len(data) {
			e.health.Malformed++
			return batch, fmt.Errorf("invalid IPFIX message length")
		}
		header = 16
		exportNs = int64(u32(data[4:])) * 1e9
		seq = u32(data[8:])
		domain = u32(data[12:])
	default:
		if len(data) >= 4 && u32(data) == 5 {
			return e.decodeSFlow(data, envelope)
		}
		e.health.Malformed++
		return batch, fmt.Errorf("unsupported flow export version %d", version)
	}
	key := scope{envelope.Exporter, envelope.Collector, version, domain}
	previous := e.domains[key]
	if previous == nil && len(e.domains) >= e.config.MaxDomains {
		e.health.StateLimitExceeded++
		return batch, fmt.Errorf("exporter domain limit exceeded: %d", e.config.MaxDomains)
	}
	state := &domainState{templates: make(map[uint16]template), sampling: Sampling{Status: "unknown", Scope: "unknown"}}
	if previous != nil {
		*state = *previous
		state.templates = make(map[uint16]template, len(previous.templates))
		for id, t := range previous.templates {
			state.templates[id] = t
		}
		if envelope.ReceivedNs > state.seen && envelope.ReceivedNs-state.seen > int64(e.config.TemplateTTL) {
			state.sampling = Sampling{Status: "unknown", Scope: "unknown"}
			state.active = nil
			state.idle = nil
		}
	}
	digest := sha256.Sum256(data)
	if state.hasSequence && seq == state.sequence && digest == state.lastDigest {
		e.health.Duplicates++
		return batch, nil
	}
	watermark := envelope.ReceivedNs
	if state.seen > watermark {
		watermark = state.seen
	}
	for id, t := range state.templates {
		if watermark > t.seen && watermark-t.seen > int64(e.config.TemplateTTL) {
			delete(state.templates, id)
			e.health.ExpiredTemplates++
		}
	}
	if version != 10 && state.hasUptime && uptime < state.uptime && !(state.uptime > 0xf0000000 && uptime < 0x10000000) && envelope.ReceivedNs >= state.seen {
		state.templates = make(map[uint16]template)
		state.sampling = Sampling{Status: "unknown", Scope: "unknown"}
		state.active = nil
		state.idle = nil
		e.health.PossibleRestarts++
		batch.Issues = append(batch.Issues, Issue{Code: "possible-exporter-restart", Envelope: envelope, Detail: "uptime regressed; templates invalidated"})
	}
	if state.hasSequence && state.expectedKnown && seq != state.expected {
		e.health.SequenceDiscontinuities++
		batch.Issues = append(batch.Issues, Issue{Code: "sequence-discontinuity", Envelope: envelope, Detail: fmt.Sprintf("expected %d, observed %d", state.expected, seq)})
	}
	var err error
	var recordCount int
	if version == 5 {
		recordCount, err = e.decodeV5(data, state, &batch, envelope, domain, seq, uptime, exportNs)
	} else {
		recordCount, err = e.decodeSets(data[header:], version, state, &batch, envelope, domain, seq, uptime, exportNs, watermark)
	}
	if err != nil {
		e.health.Malformed++
		return Batch{Observations: []Observation{}, Issues: batch.Issues}, err
	}
	count := 0
	for k, d := range e.domains {
		if k != key {
			count += len(d.templates)
		}
	}
	count += len(state.templates)
	if count > e.config.MaxTemplates {
		e.health.StateLimitExceeded++
		return Batch{}, fmt.Errorf("template limit exceeded: %d", e.config.MaxTemplates)
	}
	state.sequence, state.lastDigest, state.seen = seq, digest, watermark
	state.hasSequence = true
	state.uptime, state.hasUptime = uptime, version != 10
	state.expectedKnown = true
	for _, issue := range batch.Issues {
		if issue.Code == "missing-template" {
			state.expectedKnown = false
		}
	}
	if version == 9 {
		state.expected = seq + 1
	} else {
		state.expected = seq + uint32(recordCount)
	}
	e.domains[key] = state
	e.health.Records += uint64(len(batch.Observations))
	for i := range batch.Observations {
		obs := &batch.Observations[i]
		identity := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%x/%d/%d", envelope.Exporter, envelope.Collector, envelope.ReceivedNs, digest, envelope.PacketOrdinal, i)))
		obs.ID = hex.EncodeToString(identity[:])
	}
	return batch, nil
}

func u16(data []byte) uint16 { return binary.BigEndian.Uint16(data[:2]) }
func u32(data []byte) uint32 { return binary.BigEndian.Uint32(data[:4]) }
func number(data []byte) (uint64, error) {
	if len(data) < 1 || len(data) > 8 {
		return 0, fmt.Errorf("invalid integer width %d", len(data))
	}
	var n uint64
	for _, b := range data {
		n = n<<8 | uint64(b)
	}
	return n, nil
}
func ptr(n uint64) *uint64 { return &n }
func zero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
