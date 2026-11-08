package tcp

import (
	"bytes"
	"errors"
	"sort"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type refusedConnection struct{}

func (refusedConnection) Accept(*layers.TCP, reassembly.TCPFlowDirection, reassembly.Sequence) bool {
	return false
}
func (refusedConnection) ReassembledSG(reassembly.ScatterGather, reassembly.AssemblerContext) {}
func (refusedConnection) ReassemblyComplete(reassembly.AssemblerContext, gopacket.Flow, string) bool {
	return true
}

func ConfigureIncrementalState(b *core.StateBudget, cancel func()) {
	StreamFactory.Lock()
	defer StreamFactory.Unlock()
	StreamFactory.stateBudget, StreamFactory.stateCancel, StreamFactory.stateError = b, cancel, nil
}

func (f *connectionFactory) failIncremental(err error) {
	f.Lock()
	if f.stateError == nil {
		f.stateError = err
	}
	cancel := f.stateCancel
	f.Unlock()
	if cancel != nil {
		cancel()
	}
}

func IncrementalError() error {
	StreamFactory.Lock()
	defer StreamFactory.Unlock()
	return StreamFactory.stateError
}

// Pool retirement, rather than decoder completion, releases the fixed credit:
// retained closed FSMs still own connection metadata after their payload retires.
func (t *tcpConnection) ReassemblyRetired() {
	t.retireOnce.Do(func() { t.stateBudget.Release(t.stateCredit) })
}

func (t *tcpConnection) ReassemblyAllocationFailed() {
	t.releaseResources()
	t.ReassemblyRetired()
}

func (t *tcpConnection) pushIncremental(d *core.StreamData) {
	if err := t.incremental.Push(d); err != nil {
		t.factory.failIncremental(err)
		if errors.Is(err, core.ErrStreamStateBudget) || errors.Is(err, core.ErrIncrementalLimit) {
			t.recordDiscard(&t.retentionMarkers, "tcp-incremental-parser-budget", d.Dir, len(d.RawData), d.AssemblerContext)
		}
		t.incremental.Abort()
	}
}

func (t *tcpConnection) tryIncremental() {
	if !decoderconfig.Instance.IncrementalHTTP || t.incremental != nil || t.incrementalDeclined || t.initStage != 3 || t.clientDirection != reassembly.TCPDirClientToServer || t.roleSource != "syn" {
		return
	}
	ready := false
	for _, fragment := range t.client.DataSlice()[t.incrementalProbeIndex:] {
		if d, ok := fragment.(*core.StreamData); ok && (d.SkippedBytes != 0 || d.DiscardedBytes != 0) {
			t.incrementalDeclined = true
			return
		}
		for _, ch := range fragment.Raw() {
			t.incrementalProbeBytes++
			t.incrementalProbeTail = t.incrementalProbeTail<<8 | uint32(ch)
			if t.incrementalProbeBytes > 64<<10 {
				t.incrementalDeclined = true
				return
			}
			if t.incrementalProbeTail == 0x0d0a0d0a || t.incrementalProbeTail&0xffff == 0x0a0a {
				ready = true
				break
			}
		}
		t.incrementalProbeIndex++
		if ready {
			break
		}
	}
	if !ready {
		return
	}
	if err := t.stateBudget.Reserve(int64(t.incrementalProbeBytes)); err != nil {
		t.factory.failIncremental(err)
		t.incrementalDeclined = true
		return
	}
	defer t.stateBudget.Release(int64(t.incrementalProbeBytes))
	client := make([]byte, 0, t.incrementalProbeBytes)
	for _, fragment := range t.client.DataSlice() {
		n := min(len(fragment.Raw()), t.incrementalProbeBytes-len(client))
		client = append(client, fragment.Raw()[:n]...)
		if len(client) == t.incrementalProbeBytes {
			break
		}
	}
	// Selection remains authoritative (including IPP specialization). H2 prefaces
	// and protocol upgrades retain the completion path unless already claimed H1.
	if bytes.HasPrefix(client, []byte("PRI * HTTP/2.0")) {
		t.incrementalDeclined = true
		return
	}
	cIP, sIP := t.client.Network().Src().String(), t.client.Network().Dst().String()
	cPort, sPort := utils.DecodePort(t.client.Transport().Src().Raw()), utils.DecodePort(t.client.Transport().Dst().Raw())
	c := &core.ConversationInfo{Ident: t.ident, NetworkScope: t.networkScope, FirstClientPacket: t.client.FirstPacket(), FirstServerPacket: t.server.FirstPacket(), ClientIP: cIP, ServerIP: sIP, ClientPort: cPort, ServerPort: sPort, CommunityID: streamutils.CalcCommunityIDTCP(cIP, sIP, uint16(cPort), uint16(sPort)), TCPHandshakeComplete: true, TCPRoleSource: t.roleSource}
	for _, fragment := range t.client.DataSlice() {
		if ac, ok := fragment.Context().(interface{ GetLinkFlow() gopacket.Flow }); ok {
			flow := ac.GetLinkFlow()
			if len(flow.Src().Raw()) > 0 {
				c.ClientMAC, c.ServerMAC = flow.Src().String(), flow.Dst().String()
				break
			}
		}
	}
	sel, ok := stream.SelectDecoder(&stream.SelectionInput{Transport: core.TCP, ServerPort: sPort, PortClient: client, ScanClient: client, Conversation: c})
	if !ok || sel.Name != "HTTP" {
		t.incrementalDeclined = true
		return
	}
	factory, ok := sel.API.GetReaderFactory().(core.IncrementalFactory)
	if !ok {
		t.incrementalDeclined = true
		return
	}
	t.incremental = factory.NewIncremental(c, t.stateBudget)
	if observer, ok := t.incremental.(core.IncrementalTailObserver); ok {
		observer.SetTailObserver(func(c *core.ConversationInfo) { stream.ObserveTLSUpgrade(c, "HTTP") })
	}
	t.factory.Lock()
	t.factory.incrementalStreams++
	t.factory.Unlock()
	for _, reader := range []streamReader{t.client, t.server} {
		reader.CloseData()
		if owned, ok := reader.(*tcpStreamReader); ok && owned.done != nil {
			<-owned.done
		}
	}
	fragments := append(core.DataFragments(nil), t.client.DataSlice()...)
	fragments = append(fragments, t.server.DataSlice()...)
	sort.SliceStable(fragments, func(i, j int) bool {
		return fragments[i].CaptureInfo().Timestamp.Before(fragments[j].CaptureInfo().Timestamp)
	})
	for _, fragment := range fragments {
		t.pushIncremental(fragment.(*core.StreamData))
	}
	if !decoderconfig.Instance.SaveConns {
		serverPrefix := t.server.DataSlice()
		serverBytes := t.server.NumBytes()
		t.Lock()
		for _, reader := range []streamReader{t.client, t.server} {
			if owned, ok := reader.(*tcpStreamReader); ok {
				owned.data = nil
			}
		}
		t.merged = nil
		if t.payloadBudget != nil {
			t.payloadBudget.release(t.retainedPayloadBytes)
			t.retainedPayloadBytes = 0
		}
		t.Unlock()
		for _, fragment := range serverPrefix {
			if d, ok := fragment.(*core.StreamData); ok && (d.SkippedBytes != 0 || d.DiscardedBytes > 0) {
				t.incrementalBannerBytes = decoderconfig.Instance.BannerSize
				break
			}
			if t.incrementalBannerBytes >= decoderconfig.Instance.BannerSize {
				break
			}
			if !t.retainIncrementalBanner(reassembly.TCPDirServerToClient, fragment.Raw(), fragment.Context()) {
				break
			}
		}
		if owned, ok := t.server.(*tcpStreamReader); ok {
			t.Lock()
			owned.numBytes = serverBytes
			t.Unlock()
		}
	}
}

func (t *tcpConnection) retainIncrementalBanner(dir reassembly.TCPFlowDirection, data []byte, ac reassembly.AssemblerContext) bool {
	reader := t.client
	if dir == reassembly.TCPDirServerToClient {
		reader = t.server
	}
	n := 0
	if dir == reassembly.TCPDirServerToClient {
		n = min(len(data), max(0, decoderconfig.Instance.BannerSize-t.incrementalBannerBytes))
	}
	if n > 0 {
		if t.incrementalBanner == nil {
			capacity := decoderconfig.Instance.BannerSize
			if t.payloadBudget != nil {
				if !t.payloadBudget.reserve(int64(capacity)) {
					t.recordRetentionDiscard(dir, n, ac)
					return false
				}
				t.Lock()
				t.retainedPayloadBytes += int64(capacity)
				t.Unlock()
			}
			d := &core.StreamData{RawData: make([]byte, n, capacity), Dir: dir}
			copy(d.RawData, data[:n])
			if ac != nil {
				ci := ac.GetCaptureInfo()
				ci.AncillaryData = nil
				d.CaptureInformation = ci
				d.AssemblerContext = &context{CaptureInfo: ci}
			}
			t.incrementalBanner = d
			reader.StoreData(d)
		} else {
			t.Lock()
			t.incrementalBanner.RawData = append(t.incrementalBanner.RawData, data[:n]...)
			t.Unlock()
			if owned, ok := reader.(*tcpStreamReader); ok {
				t.Lock()
				owned.numBytes += n
				t.Unlock()
			}
		}
		t.incrementalBannerBytes += n
	}
	if owned, ok := reader.(*tcpStreamReader); ok {
		t.Lock()
		owned.numBytes += len(data) - n
		t.Unlock()
	}
	return true
}

type IncrementalHealth struct {
	Support               map[string]string `json:"support"`
	IncrementalStreams    uint64            `json:"incrementalStreams"`
	CompletedTransactions uint64            `json:"completedTransactions"`
	GapResets             uint64            `json:"gapResets"`
	DeferredTails         uint64            `json:"deferredTails"`
	CompletionOnly        map[string]uint64 `json:"completionOnlyBySelectedDecoder"`
}

func IncrementalHealthSnapshot() IncrementalHealth {
	f := StreamFactory
	f.Lock()
	defer f.Unlock()
	counts := make(map[string]uint64, len(f.completionOnly))
	for name, count := range f.completionOnly {
		counts[name] = count
	}
	return IncrementalHealth{Support: map[string]string{
		"HTTP/1":                "opt-in incremental transactions with observed SYN handshake and unambiguous roles; fixed/chunked bodies; EOF tails finalized once",
		"HTTP/2-and-upgrades":   "completion-only; an upgrade after incremental H1 retains a bounded tail for final decoding",
		"other-protocols":       "completion-only; no IncrementalFactory registered",
		"unqualified-TCP-roles": "completion-only; no early role guesses",
	}, IncrementalStreams: f.incrementalStreams, CompletedTransactions: f.incrementalCompleted, GapResets: f.incrementalGapResets, DeferredTails: f.deferredTails, CompletionOnly: counts}
}

func (f *connectionFactory) recordCompletionOnly(name string) {
	if !decoderconfig.Instance.IncrementalHTTP {
		return
	}
	if name == "" {
		name = "unselected"
	}
	f.Lock()
	defer f.Unlock()
	if f.completionOnly == nil {
		f.completionOnly = map[string]uint64{}
	}
	f.completionOnly[name]++
}
