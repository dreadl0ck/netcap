package collector

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/internal/identity"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

type recordScope struct {
	Scope        networkdetect.Scope
	Key          string
	NetworkScope string
	Ambiguous    bool
}

type recordCallback struct{ observe func(proto.Message) }

// Shared by every decoder worker, including a detached checkpoint batch.
// This accounts observation storage, not assembler/parser state or process RSS.
const maxApplicationQueueBytes = 16 << 20

func applicationObservationBytes(o networkdetect.ApplicationObservation) int64 {
	// Allow two slice slots per observation for append's spare capacity.
	return 2*int64(unsafe.Sizeof(o)) + int64(len(o.Kind)+len(o.SrcIP)+len(o.DstIP)+len(o.Method)+len(o.Path)+len(o.Host)+len(o.CommunityID)+len(o.Qualification)+len(o.Scope.Sensor)+len(o.Scope.Interface)+2*len(o.Scope.VLANs))
}

func endpoints(a string, p int32, b string, q int32) string {
	x, y := a+"/"+strconv.Itoa(int(p)), b+"/"+strconv.Itoa(int(q))
	if x > y {
		x, y = y, x
	}
	return x + "|" + y
}
func (c *Collector) initRecordAnalysis() {
	c.hostIdentity = identity.New()
	c.recordScopes = map[string]recordScope{}
	c.ipScopes = map[string]recordScope{}
	c.applicationRecords = nil
	c.applicationQueuedBytes, c.applicationPeakBytes, c.applicationQueueDrops = 0, 0, 0
	c.analysisOverflow = 0
	c.analysisUnscoped = 0
	previous := c.userRecordObserver
	sink := &atomic.Pointer[recordCallback]{}
	sink.Store(&recordCallback{observe: func(m proto.Message) {
		if previous != nil {
			previous(m)
		}
		c.observeDecodedRecord(m)
	}})
	c.recordObserverHandle = sink
	c.config.DecoderConfig.RecordObserver = func(m proto.Message) {
		if callback := sink.Load(); callback != nil {
			callback.observe(m)
		}
	}
}

func (c *Collector) detachRecordAnalysis() {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	if c.recordObserverHandle != nil {
		c.recordObserverHandle.Store(nil)
	}
	c.analysisMu.Lock()
	c.hostIdentity = nil
	c.recordScopes = nil
	c.ipScopes = nil
	c.applicationRecords = nil
	c.applicationQueuedBytes = 0
	c.applicationDetector = nil
	c.analysisMu.Unlock()
}
func (c *Collector) observeRecordScope(p gopacket.Packet, scope networkdetect.Scope) {
	if p.NetworkLayer() == nil {
		return
	}
	raw, _ := json.Marshal(scope)
	key := string(raw)
	c.analysisMu.Lock()
	defer c.analysisMu.Unlock()
	if c.hostIdentity == nil {
		return
	}
	remember := func(m map[string]recordScope, id string) {
		old, ok := m[id]
		if ok && (old.Key != key || old.NetworkScope != packetview.Scope(p)) {
			old.Ambiguous = true
			m[id] = old
			return
		}
		if !ok {
			if len(m) >= 65536 {
				c.analysisOverflow++
				return
			}
			m[id] = recordScope{Scope: scope, Key: key, NetworkScope: packetview.Scope(p)}
		}
	}
	n := p.NetworkLayer().NetworkFlow()
	a, b := n.Src().String(), n.Dst().String()
	remember(c.ipScopes, a)
	remember(c.ipScopes, b)
	if t := p.TransportLayer(); t != nil && len(t.TransportFlow().Src().Raw()) >= 2 && len(t.TransportFlow().Dst().Raw()) >= 2 {
		remember(c.recordScopes, endpoints(a, int32(binary.BigEndian.Uint16(t.TransportFlow().Src().Raw())), b, int32(binary.BigEndian.Uint16(t.TransportFlow().Dst().Raw()))))
	}
	if ll := p.LinkLayer(); ll != nil && len(ll.LinkFlow().Src().Raw()) == 6 {
		if ip, err := netip.ParseAddr(a); err == nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			c.hostIdentity.Bind(key, a, ll.LinkFlow().Src().String(), "observed-link-source")
		}
	}
}
func (c *Collector) observeDecodedRecord(m proto.Message) {
	switch m.(type) {
	case *types.HTTP, *types.File, *types.SMB, *types.Kerberos, *types.LDAP, *types.DCERPC, *types.DHCPv4:
	case *types.Secret:
		if m.(*types.Secret).Service != secret.IdentityService {
			return
		}
	default:
		return
	}
	c.analysisMu.Lock()
	defer c.analysisMu.Unlock()
	if c.hostIdentity == nil {
		return
	}
	var bound recordScope
	var ok bool
	if r, has := m.(interface {
		GetSrcIP() string
		GetDstIP() string
		GetSrcPort() int32
		GetDstPort() int32
	}); has {
		bound, ok = c.recordScopes[endpoints(r.GetSrcIP(), r.GetSrcPort(), r.GetDstIP(), r.GetDstPort())]
	}
	if r, is := m.(*types.DHCPv4); is {
		bound, ok = c.ipScopes[r.YourClientIP]
	}
	if r, is := m.(*types.Secret); is {
		if a, p, b, q, valid := secret.SecretEndpoints(r.Flow); valid {
			bound, ok = c.recordScopes[endpoints(a, p, b, q)]
		}
	}
	if !ok || bound.Ambiguous {
		c.analysisUnscoped++
		return
	}
	c.hostIdentity.Observe(bound.Key, m)
	if c.config.NetworkDetection {
		if o, yes := networkdetect.Observation(m); yes {
			o.Scope = bound.Scope
			n := applicationObservationBytes(o)
			if len(c.applicationRecords) >= 100000 || n > maxApplicationQueueBytes-c.applicationQueuedBytes {
				c.analysisOverflow++
				c.applicationQueueDrops++
				return
			}
			c.applicationQueuedBytes += n
			c.applicationPeakBytes = max(c.applicationPeakBytes, c.applicationQueuedBytes)
			c.applicationRecords = append(c.applicationRecords, o)
		}
	}
}
func (c *Collector) finishHostIdentity() error {
	if c.config.DecoderConfig.Null {
		return nil
	}
	if c.hostIdentity == nil {
		return nil
	}
	var snapshots []*types.DeviceProfile
	packet.DeviceProfiles.Lock()
	for _, dp := range packet.DeviceProfiles.Items {
		dp.Lock()
		snapshots = append(snapshots, proto.Clone(dp.DeviceProfile).(*types.DeviceProfile))
		dp.Unlock()
	}
	packet.DeviceProfiles.Unlock()
	c.analysisMu.Lock()
	for _, dp := range snapshots {
		for _, ip := range dp.DeviceIPs {
			if bound, ok := c.ipScopes[ip]; ok && !bound.Ambiguous {
				copy := *dp
				copy.DeviceIPs = []string{ip}
				c.hostIdentity.Seed(bound.Key, &copy)
			}
		}
	}
	report := c.hostIdentity.Report()
	report.Overflow += c.analysisOverflow
	report.UnscopedRecords = c.analysisUnscoped
	c.analysisMu.Unlock()
	for _, h := range report.Hosts {
		if h.HostnameState != "observed" {
			continue
		}
		if dp := packet.DeviceProfiles.FindByIP(h.IP); dp != nil {
			dp.EnrichFromDiscovery([]string{h.Hostname}, nil, nil, "")
		}
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.config.DecoderConfig.Out, identity.Filename), append(data, '\n'), 0600)
}
func (c *Collector) finishApplicationDetection(stats *networkdetect.Stats) error {
	err := c.drainApplicationDetection(true)
	c.applicationDetectionStats(stats)
	return err
}

// dispatchMu serializes the detector and alert writer; callbacks only enqueue
// under analysisMu so a decoder never waits for packet admission.
func (c *Collector) drainApplicationDetection(final bool) error {
	c.analysisMu.Lock()
	events := c.applicationRecords
	c.applicationRecords = nil
	c.analysisMu.Unlock()
	defer func() {
		var released int64
		for i := range events {
			released += applicationObservationBytes(events[i])
		}
		clear(events)
		c.analysisMu.Lock()
		c.applicationQueuedBytes -= released
		c.analysisMu.Unlock()
	}()
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if a.At != b.At {
			return a.At < b.At
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return string(x) < string(y)
	})
	e := c.applicationDetector
	if e == nil {
		return nil
	}
	for _, o := range events {
		if err := c.writeDetectionAlerts(e.Observe(o)); err != nil {
			return err
		}
	}
	if final {
		return c.writeDetectionAlerts(e.Flush())
	}
	return c.writeDetectionAlerts(e.Checkpoint())
}

func (c *Collector) applicationDetectionStats(stats *networkdetect.Stats) {
	e := c.applicationDetector
	if e == nil {
		return
	}
	c.analysisMu.Lock()
	overflow := c.analysisOverflow
	stats.ApplicationQueuedBytes = c.applicationQueuedBytes
	stats.ApplicationPeakBytes = c.applicationPeakBytes
	stats.ApplicationQueueDrops = c.applicationQueueDrops
	stats.ApplicationQueueLimit = maxApplicationQueueBytes
	c.analysisMu.Unlock()
	if c.captureKind == "live" {
		stats.ApplicationMode = "capture-time sorted checkpoint batches; older decoded observations counted late; wall clock does not advance event time"
	}
	stats.Alerts += e.Alerts
	stats.ApplicationAlerts = e.Alerts
	stats.Overflow += overflow + e.Overflow
	matches, capacity := e.AggregationStats()
	stats.Matches += matches
	stats.CapacityFlushes += capacity
	stats.Late += e.Late
	stats.ApplicationLate = e.Late
}
