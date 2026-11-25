package flow

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/types"
)

const (
	rotationPeers      = 5
	rotationWindow     = int64(300 * time.Second)
	rotationFailureMax = int64(10 * time.Second)
	rotationRowLimit   = 100_000
	rotationWorkLimit  = 2_000_000
	rotationHitLimit   = 1000
	rotationPeerSample = 32
)

type RotationPeer struct {
	IP            netip.Addr `json:"ip"`
	Ordinal       int        `json:"connectionOrdinal"`
	ObservationID string     `json:"observationId"`
	First         int64      `json:"firstNs,string"`
	Last          int64      `json:"lastNs,string"`
}

type RotationCandidate struct {
	Scope            string         `json:"scope"`
	Client           netip.Addr     `json:"client"`
	Port             uint16         `json:"port"`
	FailedPeersTotal int            `json:"failedPeersTotal"`
	FailedPeers      []RotationPeer `json:"failedPeers"`
	Responder        RotationPeer   `json:"responder"`
	ConfirmedAt      int64          `json:"confirmedAtNs,string"`
	PayloadOrdinals  [2]int         `json:"tcpPayloadOrdinalsClientServer"`
}

type rotationKey struct {
	scope  string
	client netip.Addr
	port   uint16
}

type rotationTuple struct{ a, b netip.AddrPort }

func rotationAddrPort(ip string, port uint64) netip.AddrPort {
	if len(ip) > 64 || port == 0 || port > 65535 {
		return netip.AddrPort{}
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port))
}

func (t rotationTuple) ordered() rotationTuple {
	if t.a.Compare(t.b) > 0 {
		return rotationTuple{t.b, t.a}
	}
	return t
}

type rotationObservation struct {
	peer            RotationPeer
	tuple           rotationTuple
	scope, cid      string
	sequence        uint64
	fails, responds bool
}

func (o rotationObservation) key() rotationKey {
	return rotationKey{o.scope, o.tuple.a.Addr(), o.tuple.b.Port()}
}

type rotationIndex struct {
	rows       []rotationObservation
	identities map[string]int
}

func (i *rotationIndex) add(c *types.Connection, ordinal int) error {
	if c.TransportProto != "TCP" {
		return nil
	}
	sp, _ := strconv.ParseUint(c.SrcPort, 10, 16)
	dp, _ := strconv.ParseUint(c.DstPort, 10, 16)
	tuple := rotationTuple{rotationAddrPort(c.SrcIP, sp), rotationAddrPort(c.DstIP, dp)}
	if !tuple.a.IsValid() || !tuple.b.IsValid() || tuple.a == tuple.b {
		return fmt.Errorf("invalid TCP transport tuple at Connection ordinal %d", ordinal)
	}
	if len(c.ObservationID) > 128 || len(c.NetworkScope) > 512 || len(c.CommunityID) > 128 {
		return fmt.Errorf("Connection identity exceeds limits at ordinal %d", ordinal)
	}
	peer := RotationPeer{tuple.b.Addr(), ordinal, c.ObservationID, c.TimestampFirst, c.TimestampLast}
	o := rotationObservation{peer: peer, tuple: tuple, scope: c.NetworkScope, cid: c.CommunityID, sequence: c.SnapshotSequence}
	identified := c.ObservationID != "" && c.SnapshotSequence > 0 && c.CounterSemantics == "tuple-cumulative"
	if identified && c.NetworkScope != "" && c.TCPInitiatorObserved && (c.Normalization == "" || c.Normalization == "complete") &&
		peer.First > 0 && peer.Last >= peer.First && tuple.a.Addr() != peer.IP && peer.IP.IsGlobalUnicast() && filter.IsPublicIP(peer.IP.String()) {
		hasPayload := c.AppPayloadSize64 > 0 || c.AppPayloadSize > 0
		o.fails = !c.Established && c.AppPayloadSize64 == 0 && c.AppPayloadSize == 0 && c.NumSYNFlags > 0 &&
			c.SynAckTimestamp == 0 && (c.PacketsServerToClient == 0 || c.NumRSTFlags > 0) && peer.Last-peer.First <= rotationFailureMax
		o.responds = hasPayload && c.PacketsClientToServer > 0 && c.PacketsServerToClient > 0 && c.CommunityID != ""
	}
	if identified {
		if i.identities == nil {
			i.identities = make(map[string]int)
		}
		if idx, ok := i.identities[c.ObservationID]; ok {
			old := i.rows[idx]
			if old.scope != o.scope || old.tuple.ordered() != o.tuple.ordered() {
				return fmt.Errorf("conflicting Connection identity at ordinal %d", ordinal)
			}
			if old.sequence == o.sequence {
				old.peer.Ordinal = ordinal
				if old != o {
					return fmt.Errorf("conflicting Connection snapshot at ordinal %d", ordinal)
				}
			} else if old.sequence < o.sequence {
				i.rows[idx] = o
			}
			return nil
		}
		i.identities[c.ObservationID] = len(i.rows)
	}
	i.rows = append(i.rows, o)
	return nil
}

type rotationWitness struct {
	row      int
	at       [2]int64
	ordinals [2]int
}

func (i rotationIndex) prepare() (map[rotationKey][]RotationPeer, map[rotationTuple]*rotationWitness) {
	failures := make(map[rotationKey][]RotationPeer)
	counts := make(map[rotationTuple]int)
	for _, o := range i.rows {
		if o.fails {
			failures[o.key()] = append(failures[o.key()], o.peer)
		}
		counts[o.tuple.ordered()]++
	}
	for _, peers := range failures {
		slices.SortFunc(peers, func(a, b RotationPeer) int {
			return cmp.Or(cmp.Compare(a.Last, b.Last), cmp.Compare(a.Ordinal, b.Ordinal))
		})
	}
	witnesses := make(map[rotationTuple]*rotationWitness)
	for row, o := range i.rows {
		tuple := o.tuple.ordered()
		// TCP rows do not carry scope. Never guess which observation owned a reused tuple.
		if o.responds && len(failures[o.key()]) >= rotationPeers && counts[tuple] == 1 {
			witnesses[tuple] = &rotationWitness{row: row}
		}
	}
	return failures, witnesses
}

func (i rotationIndex) observePayload(witnesses map[rotationTuple]*rotationWitness, p *types.TCP, ordinal int) {
	if p.PayloadSize <= 0 || p.SYN || p.RST {
		return
	}
	tuple := rotationTuple{rotationAddrPort(p.SrcIP, uint64(p.SrcPort)), rotationAddrPort(p.DstIP, uint64(p.DstPort))}
	w := witnesses[tuple.ordered()]
	if w == nil {
		return
	}
	o := i.rows[w.row]
	if p.CommunityID != o.cid || p.Timestamp < o.peer.First || p.Timestamp > o.peer.Last {
		return
	}
	direction := 0
	if tuple != o.tuple {
		direction = 1
	}
	if w.at[direction] == 0 || p.Timestamp < w.at[direction] {
		w.at[direction], w.ordinals[direction] = p.Timestamp, ordinal
	}
}

func (i rotationIndex) candidates(ctx context.Context, failures map[rotationKey][]RotationPeer, witnesses map[rotationTuple]*rotationWitness) ([]RotationCandidate, error) {
	confirmed := make([]*rotationWitness, 0, len(witnesses))
	for _, w := range witnesses {
		if w.at[0] != 0 && w.at[1] != 0 {
			confirmed = append(confirmed, w)
		}
	}
	slices.SortFunc(confirmed, func(a, b *rotationWitness) int {
		return cmp.Or(cmp.Compare(max(a.at[0], a.at[1]), max(b.at[0], b.at[1])), cmp.Compare(i.rows[a.row].peer.Ordinal, i.rows[b.row].peer.Ordinal))
	})
	result := []RotationCandidate{}
	work := rotationWorkLimit
	through := make(map[rotationKey]int64)
	for _, w := range confirmed {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		o := i.rows[w.row]
		key := o.key()
		at := max(w.at[0], w.at[1])
		cutoff := at - rotationWindow
		previous := through[key]
		peers := failures[key]
		end := sort.Search(len(peers), func(n int) bool { return peers[n].Last >= o.peer.First })
		seen := make(map[netip.Addr]bool)
		var sample []RotationPeer
		for n := end - 1; n >= 0 && peers[n].Last >= cutoff && peers[n].Last > previous; n-- {
			work--
			if work < 0 {
				return nil, fmt.Errorf("peer rotation comparison limit exceeded")
			}
			p := peers[n]
			if p.First < cutoff || p.First <= previous || p.IP == o.peer.IP || seen[p.IP] {
				continue
			}
			seen[p.IP] = true
			if len(sample) < rotationPeerSample {
				sample = append(sample, p)
			}
		}
		if len(seen) >= rotationPeers {
			if len(result) == rotationHitLimit {
				return nil, fmt.Errorf("peer rotation candidate limit exceeded")
			}
			result = append(result, RotationCandidate{key.scope, key.client, key.port, len(seen), sample, o.peer, at, w.ordinals})
			// Treat follow-up responders to the same burst as one episode.
			through[key] = at
		}
	}
	return result, nil
}
