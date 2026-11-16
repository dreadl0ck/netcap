package reassembly

import (
	"container/list"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/packetmeta"
)

// ColdStream keeps control-only validation state recoverable without live readers.
type ColdStream interface {
	Stream
	ColdEligible() bool
	SaveColdState() ([]byte, error)
	ColdSuspended()
}

type ColdFactory interface {
	RestoreColdState([]byte, bool) (Stream, error)
}

type coldHalf struct {
	Flow                                                                 FlowState
	Created, LastSeen, FirstSeen                                         TimeState
	Ack, Next, FINSeq                                                    Sequence
	OverlapPackets, OverlapBytes, QueuedBytes, QueuedPackets, TotalBytes int
	Closed, SYNSeen, FINSeen, FINPending                                 bool
	SYNSeq                                                               uint32
	Direction                                                            TCPFlowDirection
}

type coldConnection struct {
	Version                 int
	Key                     [3]FlowState
	Halves                  [2]coldHalf
	Context                 []byte
	FirstFlow               FlowState
	ResetSeen, ObserveClose bool
	Stream                  []byte
}

type coldStorage struct {
	state   *aggregate.Store
	factory ColdFactory
	prefix  string
	limit   int
	hot     list.List // Protected by StreamPool.mu.
	count   atomic.Int64
}

var coldPoolSequence atomic.Uint64

type ControlStorageHealth struct {
	ResidentControls, ResidentConnections, Limit int
	StoredControls                               int64
}

func (p *StreamPool) ControlStorageHealth() ControlStorageHealth {
	p.mu.RLock()
	defer p.mu.RUnlock()
	health := ControlStorageHealth{ResidentConnections: len(p.conns)}
	if p.cold != nil {
		health.ResidentControls, health.Limit, health.StoredControls = p.cold.hot.Len(), p.cold.limit, p.cold.count.Load()
	}
	return health
}

func (p *StreamPool) EnableColdStorage(state *aggregate.Store, hotControls int) error {
	factory, ok := p.factory.(ColdFactory)
	if !ok || state == nil || hotControls < 1 || len(p.conns) != 0 {
		return fmt.Errorf("invalid TCP cold-storage configuration")
	}
	id := coldPoolSequence.Add(1)
	if id == 0 {
		return fmt.Errorf("TCP pool namespace exhausted")
	}
	p.cold = &coldStorage{state: state, factory: factory, prefix: fmt.Sprintf("tcp/control/%016x/", id), limit: hotControls}
	return nil
}

func coldID(k *key) string {
	wire := []byte{}
	for _, flow := range k {
		wire = binary.AppendVarint(wire, int64(flow.EndpointType()))
		wire = append(wire, byte(len(flow.Src().Raw())), byte(len(flow.Dst().Raw())))
		wire = append(wire, flow.Src().Raw()...)
		wire = append(wire, flow.Dst().Raw()...)
	}
	return base64.RawURLEncoding.EncodeToString(wire)
}

func saveColdHalf(h *halfconnection) coldHalf {
	return coldHalf{Flow: SaveFlow(h.flow), Created: SaveTime(h.created), LastSeen: SaveTime(h.lastSeen), FirstSeen: SaveTime(h.firstSeen),
		Ack: h.ackSeq, Next: h.nextSeq, FINSeq: h.finSeq, OverlapPackets: h.overlapPackets, OverlapBytes: h.overlapBytes,
		QueuedBytes: h.queuedBytes, QueuedPackets: h.queuedPackets, TotalBytes: h.totalBytes,
		Closed: h.closed, SYNSeen: h.synSeen, FINSeen: h.finSeen, FINPending: h.finPending, SYNSeq: h.synSeq, Direction: h.dir}
}

func (h coldHalf) restore(stream Stream) (halfconnection, error) {
	flow, err := h.Flow.Restore()
	if err != nil {
		return halfconnection{}, err
	}
	created, err := h.Created.Restore()
	if err != nil {
		return halfconnection{}, err
	}
	last, err := h.LastSeen.Restore()
	if err != nil {
		return halfconnection{}, err
	}
	first, err := h.FirstSeen.Restore()
	if err != nil {
		return halfconnection{}, err
	}
	return halfconnection{flow: flow, created: created, lastSeen: last, firstSeen: first, stream: stream,
		ackSeq: h.Ack, nextSeq: h.Next, finSeq: h.FINSeq, overlapPackets: h.OverlapPackets, overlapBytes: h.OverlapBytes,
		queuedBytes: h.QueuedBytes, queuedPackets: h.QueuedPackets, totalBytes: h.TotalBytes,
		closed: h.Closed, synSeen: h.SYNSeen, finSeen: h.FINSeen, finPending: h.FINPending, synSeq: h.SYNSeq, dir: h.Direction}, nil
}

func canStoreCold(c *connection) bool {
	stream, ok := c.c2s.stream.(ColdStream)
	return ok && stream.ColdEligible() && c.c2s.pages == 0 && c.s2c.pages == 0 && c.c2s.first == nil && c.s2c.first == nil && c.c2s.saved == nil && c.s2c.saved == nil
}

// Caller holds conn.mu; queue membership never retains an evicted generation.
func (p *StreamPool) refreshColdLocked(c *connection) {
	if p.cold == nil || !c.live {
		return
	}
	eligible := canStoreCold(c)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !eligible {
		p.removeColdHotLocked(c)
	} else if c.coldHot == nil {
		c.coldHot = p.cold.hot.PushBack(connectionRef{conn: c, generation: c.generation})
	} else {
		p.cold.hot.MoveToBack(c.coldHot)
	}
}

func (p *StreamPool) removeColdHotLocked(c *connection) {
	if c.coldHot != nil {
		p.cold.hot.Remove(c.coldHot)
		c.coldHot = nil
	}
}

func snapshotCold(c *connection) (coldConnection, error) {
	s := coldConnection{Version: 1, Key: [3]FlowState{SaveFlow(c.key[0]), SaveFlow(c.key[1]), SaveFlow(c.key[2])},
		Halves: [2]coldHalf{saveColdHalf(&c.c2s), saveColdHalf(&c.s2c)}, FirstFlow: SaveFlow(c.firstFlow), ResetSeen: c.resetSeen, ObserveClose: c.observeClose}
	var err error
	s.Context, err = packetmeta.Marshal(c.ac.GetCaptureInfo())
	if err != nil {
		return s, err
	}
	s.Stream, err = c.c2s.stream.(ColdStream).SaveColdState()
	return s, err
}

func decodeCold(wire []byte) (coldConnection, error) {
	var s coldConnection
	if len(wire) > 16<<20 {
		return s, fmt.Errorf("stored TCP control record exceeds limit")
	}
	if err := json.Unmarshal(wire, &s); err != nil {
		return s, err
	}
	if s.Version != 1 {
		return s, fmt.Errorf("invalid TCP control record version")
	}
	return s, nil
}

func (s coldConnection) lastSeen() (time.Time, error) {
	a, err := s.Halves[0].LastSeen.Restore()
	if err != nil {
		return a, err
	}
	b, err := s.Halves[1].LastSeen.Restore()
	if err != nil {
		return b, err
	}
	if a.Before(b) {
		return b, nil
	}
	return a, nil
}

func (s *coldStorage) row(id string) string { return s.prefix + "states/" + id + "/" }

func (s *coldStorage) index(id string, c coldConnection, idle bool) (string, error) {
	kind := "closed/"
	if !c.ObserveClose && !(c.Halves[0].Closed && c.Halves[1].Closed) {
		if !idle {
			return "", nil
		}
		kind = "idle/"
	}
	stamp, err := c.lastSeen()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%sdue/%s%016x/%08x/%s/", s.prefix, kind, uint64(stamp.Unix())^(uint64(1)<<63), uint32(stamp.Nanosecond()), id), nil
}

func (s *coldStorage) put(tx *aggregate.Tx, id string, c coldConnection, idle bool) error {
	wire, err := json.Marshal(c)
	if err != nil {
		return err
	}
	index, err := s.index(id, c, idle)
	if err != nil {
		return err
	}
	if err := tx.Put(s.row(id), wire); err != nil {
		return err
	}
	if index != "" {
		return tx.Put(index, []byte(id))
	}
	return nil
}

func (s *coldStorage) erase(tx *aggregate.Tx, id string, c coldConnection, idle bool) error {
	index, err := s.index(id, c, idle)
	if err != nil {
		return err
	}
	if index != "" {
		if err := tx.Delete(index); err != nil {
			return err
		}
	}
	return tx.Delete(s.row(id))
}

func (p *StreamPool) makeColdRoom() error {
	if p.cold == nil {
		return nil
	}
	for {
		p.mu.Lock()
		if p.cold.hot.Len() < p.cold.limit {
			p.mu.Unlock()
			return nil
		}
		ref := p.cold.hot.Front().Value.(connectionRef)
		p.mu.Unlock()
		if !ref.lock() {
			continue
		}
		c := ref.conn
		if !canStoreCold(c) {
			p.refreshColdLocked(c)
			c.mu.Unlock()
			continue
		}
		snap, err := snapshotCold(c)
		if err == nil {
			err = p.cold.state.Do(func(tx *aggregate.Tx) error { return p.cold.put(tx, coldID(c.key), snap, p.trackIdle) })
		}
		if err != nil {
			c.mu.Unlock()
			_ = p.cold.state.Do(func(*aggregate.Tx) error { return err })
			return err
		}
		c.c2s.stream.(ColdStream).ColdSuspended()
		p.mu.Lock()
		p.removeColdHotLocked(c)
		if c.connectionDue != nil {
			p.pendingDue.remove(&c.pendingEntry)
			p.closedDue.remove(&c.closedEntry)
			p.idleDue.remove(&c.idleEntry)
		}
		delete(p.conns, *c.key)
		c.live = false
		c.c2s.stream, c.s2c.stream = nil, nil
		p.free = append(p.free, c)
		p.cold.count.Add(1)
		p.mu.Unlock()
		c.mu.Unlock()
	}
}

func (p *StreamPool) restoreCold(k *key) (connectionRef, bool, bool, error) {
	if p.cold == nil {
		return connectionRef{}, false, false, nil
	}
	var snap coldConnection
	var found, reverse bool
	id := coldID(k)
	err := p.cold.state.Do(func(tx *aggregate.Tx) error {
		wire, exists, err := tx.Get(p.cold.row(id))
		if err != nil {
			return err
		}
		if !exists {
			rk := k.reverse()
			id = coldID(&rk)
			wire, exists, err = tx.Get(p.cold.row(id))
			reverse = exists
		}
		found = exists
		if err != nil || !exists {
			return err
		}
		snap, err = decodeCold(wire)
		return err
	})
	if err != nil || !found {
		return connectionRef{}, reverse, found, err
	}
	if err := p.makeColdRoom(); err != nil {
		return connectionRef{}, reverse, true, err
	}
	var stored key
	for i := range stored {
		stored[i], err = snap.Key[i].Restore()
		if err != nil {
			return connectionRef{}, reverse, true, err
		}
	}
	stream, err := p.cold.factory.RestoreColdState(snap.Stream, true)
	if err != nil {
		return connectionRef{}, reverse, true, err
	}
	created, err := snap.Halves[0].Created.Restore()
	if err != nil {
		stream.(ColdStream).ColdSuspended()
		return connectionRef{}, reverse, true, err
	}
	c := p.newConnection(&stored, stream, created)
	if c == nil {
		stream.(ColdStream).ColdSuspended()
		return connectionRef{}, reverse, true, fmt.Errorf("TCP control restore allocation failed")
	}
	c.c2s, err = snap.Halves[0].restore(stream)
	if err == nil {
		c.s2c, err = snap.Halves[1].restore(stream)
	}
	if err == nil {
		c.firstFlow, err = snap.FirstFlow.Restore()
	}
	if err == nil {
		ci, decodeErr := packetmeta.Unmarshal(snap.Context)
		err = decodeErr
		c.ac = assemblerSimpleContext(ci)
	}
	c.resetSeen, c.observeClose = snap.ResetSeen, snap.ObserveClose
	if err == nil {
		err = p.cold.state.Do(func(tx *aggregate.Tx) error { return p.cold.erase(tx, id, snap, p.trackIdle) })
	}
	if err != nil {
		stream.(ColdStream).ColdSuspended()
		p.mu.Lock()
		c.live = false
		c.c2s.stream, c.s2c.stream = nil, nil
		p.free = append(p.free, c)
		p.mu.Unlock()
		return connectionRef{}, reverse, true, err
	}
	p.mu.Lock()
	p.conns[stored] = c
	p.cold.count.Add(-1)
	p.mu.Unlock()
	return connectionRef{conn: c, generation: c.generation}, reverse, true, nil
}

// Retire or close one serialized control stream without materializing a pool slot.
func (p *StreamPool) finishCold(id string, snap coldConnection, reason string, retire bool) error {
	stream, err := p.cold.factory.RestoreColdState(snap.Stream, false)
	if err != nil {
		return err
	}
	if !retire && !(snap.Halves[0].Closed && snap.Halves[1].Closed) {
		ci, err := packetmeta.Unmarshal(snap.Context)
		if err != nil {
			return err
		}
		index := 1
		first, err := snap.Halves[0].FirstSeen.Restore()
		if err != nil {
			return err
		}
		other, err := snap.Halves[1].FirstSeen.Restore()
		if err != nil {
			return err
		}
		if first.Before(other) {
			index = 0
		}
		ci.Timestamp, err = snap.Halves[index].FirstSeen.Restore()
		if err != nil {
			return err
		}
		flow, err := snap.Halves[index].Flow.Restore()
		if err != nil {
			return err
		}
		ac := assemblerSimpleContext(ci)
		retire = stream.ReassemblyComplete(&ac, flow, reason)
		snap.Halves[0].Closed, snap.Halves[1].Closed = true, true
		snap.Context, err = packetmeta.Marshal(ci)
		if err != nil {
			return err
		}
		snap.FirstFlow = SaveFlow(flow)
		snap.Stream, err = stream.(ColdStream).SaveColdState()
		if err != nil {
			return err
		}
	}
	err = p.cold.state.Do(func(tx *aggregate.Tx) error {
		wire, found, err := tx.Get(p.cold.row(id))
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("TCP cold state disappeared during completion")
		}
		previous, err := decodeCold(wire)
		if err != nil {
			return err
		}
		if err = p.cold.erase(tx, id, previous, p.trackIdle); err != nil {
			return err
		}
		if !retire {
			return p.cold.put(tx, id, snap, p.trackIdle)
		}
		return nil
	})
	if err == nil && retire {
		if observer, ok := stream.(interface{ ReassemblyRetired() }); ok {
			observer.ReassemblyRetired()
		}
		p.cold.count.Add(-1)
	}
	return err
}

func (p *StreamPool) flushColdAll(retire bool) (count int) {
	if p.cold == nil {
		return 0
	}
	p.createMu.Lock()
	defer p.createMu.Unlock()
	last := ""
	for {
		var key string
		var snap coldConnection
		var found bool
		err := p.cold.state.Do(func(tx *aggregate.Tx) error {
			var wire []byte
			var err error
			key, wire, found, err = tx.Next(p.cold.prefix+"states/", last)
			if err != nil || !found {
				return err
			}
			snap, err = decodeCold(wire)
			return err
		})
		if err != nil || !found {
			return count
		}
		id := strings.TrimSuffix(strings.TrimPrefix(key, p.cold.prefix+"states/"), "/")
		if err := p.finishCold(id, snap, "no bytes saved", retire); err != nil {
			_ = p.cold.state.Do(func(*aggregate.Tx) error { return err })
			return count
		}
		count++
		last = key
	}
}

func (p *StreamPool) flushColdDue(opt FlushOptions) (closed int) {
	if p.cold == nil {
		return 0
	}
	p.createMu.Lock()
	defer p.createMu.Unlock()
	for _, queue := range []struct {
		name   string
		cutoff time.Time
	}{{"closed/", opt.TC}, {"idle/", opt.TI}} {
		if queue.name == "idle/" && (opt.TI.IsZero() || !p.trackIdle) {
			continue
		}
		for {
			var id string
			var snap coldConnection
			var found bool
			err := p.cold.state.Do(func(tx *aggregate.Tx) error {
				_, value, exists, err := tx.Next(p.cold.prefix+"due/"+queue.name, "")
				if err != nil || !exists {
					return err
				}
				id = string(value)
				wire, exists, err := tx.Get(p.cold.row(id))
				if err != nil {
					return err
				}
				if !exists {
					return fmt.Errorf("TCP cold deadline has no state")
				}
				snap, err = decodeCold(wire)
				if err != nil {
					return err
				}
				stamp, err := snap.lastSeen()
				if err != nil {
					return err
				}
				found = stamp.Before(queue.cutoff)
				return nil
			})
			if err != nil || !found {
				break
			}
			retire := snap.Halves[0].Closed && snap.Halves[1].Closed
			reason := "idle-expired"
			if snap.ObserveClose {
				reason = "post-close-observation-expired"
			}
			open := 0
			for _, half := range snap.Halves {
				if !half.Closed {
					open++
				}
			}
			if err := p.finishCold(id, snap, reason, retire); err != nil {
				_ = p.cold.state.Do(func(*aggregate.Tx) error { return err })
				return closed
			}
			closed += open
		}
	}
	return closed
}
