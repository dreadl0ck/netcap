//go:build !nodpi

package dpi

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	dpitypes "github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type incrementalKey struct {
	endpoints [36]byte
	protocol  uint8
	version   uint8
}

// Canonicalize address+port pairs together, including when both ports are equal.
func packetKey(packet gopacket.Packet) (incrementalKey, int, bool) {
	var key incrementalKey
	if packet == nil {
		return key, 0, false
	}
	network, transport := packet.NetworkLayer(), packet.TransportLayer()
	if network == nil || transport == nil {
		return key, 0, false
	}
	src, dst := network.NetworkFlow().Endpoints()
	sp, dp := transport.TransportFlow().Endpoints()
	if len(src.Raw()) != len(dst.Raw()) || (len(src.Raw()) != 4 && len(src.Raw()) != 16) || len(sp.Raw()) != 2 || len(dp.Raw()) != 2 {
		return key, 0, false
	}
	switch transport.LayerType() {
	case layers.LayerTypeTCP:
		key.protocol = 6
	case layers.LayerTypeUDP:
		key.protocol = 17
	case layers.LayerTypeSCTP:
		key.protocol = 132
	default:
		return key, 0, false
	}
	key.version = uint8(len(src.Raw()))
	copy(key.endpoints[:16], src.Raw())
	copy(key.endpoints[16:18], sp.Raw())
	copy(key.endpoints[18:34], dst.Raw())
	copy(key.endpoints[34:], dp.Raw())
	direction := 0
	if bytes.Compare(key.endpoints[:18], key.endpoints[18:]) > 0 {
		var endpoint [18]byte
		copy(endpoint[:], key.endpoints[:18])
		copy(key.endpoints[:18], key.endpoints[18:])
		copy(key.endpoints[18:], endpoint[:])
		direction = 1
	}
	return key, direction, true
}

func (key incrementalKey) hash() uint64 {
	// Mix both address-port endpoints; fixed high bits must not put every flow on one shard.
	h := uint64(14695981039346656037)
	for _, b := range key.endpoints {
		h = (h ^ uint64(b)) * 1099511628211
	}
	return (h ^ uint64(key.protocol) ^ uint64(key.version)<<8) * 1099511628211
}

type incrementalEntry struct {
	key              incrementalKey
	native           wrappers.IncrementalFlow
	goFlow           *dpitypes.Flow
	goResults        []dpitypes.ClassificationResult
	packets          uint8
	initialDirection uint8
	lastSeen         time.Time
	previous, next   *incrementalEntry
}

type incrementalShard struct {
	sync.Mutex
	worker       *wrappers.IncrementalWorker
	goModule     *classifiers.ClassifierModule
	flows        map[incrementalKey]*incrementalEntry
	head, tail   *incrementalEntry
	limit        int
	ttl          time.Duration
	processed    uint64
	lastMetadata *gopacket.PacketMetadata
	lastEntry    *incrementalEntry
}

type incrementalPool struct {
	shards     []*incrementalShard
	stop, done chan struct{}
}

func newIncrementalPool(modules map[string]bool, workers, limit int, ttl time.Duration) (*incrementalPool, error) {
	if workers < 1 || limit < 1 || ttl <= 0 {
		return nil, fmt.Errorf("invalid DPI pool configuration")
	}
	p := &incrementalPool{}
	for i := 0; i < workers; i++ {
		worker, err := wrappers.NewIncrementalWorker(modules["ndpi"], modules["lpi"])
		if err != nil {
			p.close()
			return nil, err
		}
		s := &incrementalShard{worker: worker, flows: make(map[incrementalKey]*incrementalEntry), limit: limit, ttl: ttl}
		if modules["go"] {
			s.goModule = classifiers.NewClassifierModule()
		}
		p.shards = append(p.shards, s)
	}
	p.stop, p.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(max(time.Nanosecond, min(ttl/2, time.Minute)))
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case now := <-ticker.C:
				for _, s := range p.shards {
					s.Lock()
					s.expire(now)
					s.Unlock()
				}
			}
		}
	}()
	return p, nil
}

func configuredIncrementalPool(modules map[string]bool, config RuntimeConfig) (*incrementalPool, error) {
	if config.Workers < 0 || config.MaxFlows < 0 || config.IdleTimeout < 0 {
		return nil, fmt.Errorf("negative DPI configuration")
	}
	if config.Workers == 0 {
		config.Workers = min(runtime.GOMAXPROCS(0), 8)
	}
	if config.MaxFlows == 0 {
		config.MaxFlows = 65536
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	config.Workers = min(config.Workers, config.MaxFlows)
	p, err := newIncrementalPool(modules, config.Workers, config.MaxFlows/config.Workers, config.IdleTimeout)
	if err != nil {
		return nil, err
	}
	for i := 0; i < config.MaxFlows%config.Workers; i++ {
		p.shards[i].limit++
	}
	return p, nil
}

func (s *incrementalShard) unlink(f *incrementalEntry) {
	if f.previous != nil {
		f.previous.next = f.next
	} else {
		s.head = f.next
	}
	if f.next != nil {
		f.next.previous = f.previous
	} else {
		s.tail = f.previous
	}
	f.previous, f.next = nil, nil
}

func (s *incrementalShard) touch(f *incrementalEntry, now time.Time) {
	if s.tail != f {
		if f.previous != nil || f.next != nil || s.head == f {
			s.unlink(f)
		}
		f.previous = s.tail
		if s.tail != nil {
			s.tail.next = f
		} else {
			s.head = f
		}
		s.tail = f
	}
	f.lastSeen = now
}

func (s *incrementalShard) remove(f *incrementalEntry) {
	if s.lastEntry == f {
		s.lastEntry, s.lastMetadata = nil, nil
	}
	s.worker.Free(&f.native)
	s.unlink(f)
	delete(s.flows, f.key)
}

func (p *incrementalPool) flush() {
	for _, s := range p.shards {
		s.Lock()
		for s.head != nil {
			s.remove(s.head)
		}
		s.Unlock()
	}
}

func (p *incrementalPool) close() {
	if p.stop != nil {
		close(p.stop)
		<-p.done
		p.stop = nil
	}
	p.flush()
	for _, s := range p.shards {
		s.worker.Close()
	}
}

func (s *incrementalShard) expire(now time.Time) {
	for s.head != nil && now.Sub(s.head.lastSeen) >= s.ttl {
		s.remove(s.head)
	}
}

func (p *incrementalPool) classify(packet gopacket.Packet) map[string]dpitypes.ClassificationResult {
	key, direction, valid := packetKey(packet)
	if !valid {
		return nil
	}
	s := p.shards[key.hash()%uint64(len(p.shards))]
	s.Lock()
	defer s.Unlock()
	now := time.Now()
	s.expire(now)
	// Enrichment decoders may ask about the same packet. Retain one identity per shard.
	if s.lastMetadata == packet.Metadata() && s.lastEntry != nil && s.lastEntry.key == key {
		return s.lastEntry.protocols()
	}
	f := s.flows[key]
	if f == nil {
		if len(s.flows) >= s.limit {
			s.remove(s.head)
		}
		f = &incrementalEntry{key: key, initialDirection: uint8(direction)}
		if s.goModule != nil {
			f.goFlow = dpitypes.NewFlow()
		}
		s.flows[key] = f
	}
	s.touch(f, now)
	s.lastMetadata, s.lastEntry = packet.Metadata(), f
	if f.packets < dpitypes.MaxPacketsPerFlow && (!s.worker.Complete(&f.native) || f.goFlow != nil) {
		f.packets++
		final := f.packets == dpitypes.MaxPacketsPerFlow
		ip := packet.NetworkLayer().LayerContents()
		// Network-layer content and payload are adjacent in a decoded packet's capture buffer.
		// Use the offset in Data rather than allocating a concatenated IP packet.
		data := packet.Data()
		start := 0
		for _, layer := range packet.Layers() {
			if layer == packet.NetworkLayer() {
				break
			}
			start += len(layer.LayerContents())
		}
		ipLength := len(ip) + len(packet.NetworkLayer().LayerPayload())
		if start >= 0 && ipLength <= len(data)-start {
			ip = data[start : start+ipLength]
		}
		var ethernet []byte
		if packet.LinkLayer() != nil && packet.LinkLayer().LayerType() == layers.LayerTypeEthernet {
			ethernet = data
		}
		millis := packet.Metadata().Timestamp.UnixMilli()
		if millis < 0 {
			millis = 0
		}
		_ = s.worker.Process(&f.native, ip, ethernet, uint64(millis), direction^int(f.initialDirection), final)
		s.processed++
		if f.goFlow != nil {
			f.goFlow.AddPacket(packet)
			f.goResults = s.goModule.ClassifyFlowAll(f.goFlow)
			if final || len(f.goResults) > 0 {
				f.goFlow = nil
			}
		}
	}
	return f.protocols()
}

func (f *incrementalEntry) protocols() map[string]dpitypes.ClassificationResult {
	if f.native.Count == 0 && len(f.goResults) == 0 {
		return nil
	}
	result := make(map[string]dpitypes.ClassificationResult, f.native.Count+len(f.goResults))
	for _, r := range f.native.Results[:f.native.Count] {
		if _, exists := result[string(r.Protocol)]; !exists {
			result[string(r.Protocol)] = r
		}
	}
	for _, r := range f.goResults {
		if _, exists := result[string(r.Protocol)]; !exists {
			result[string(r.Protocol)] = r
		}
	}
	return result
}
