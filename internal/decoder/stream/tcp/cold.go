package tcp

import (
	"encoding/json"
	"fmt"
	"strings"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

type coldTCPState struct {
	Version                                              int
	Network, Transport                                   reassembly.FlowState
	Validation                                           reassembly.TCPValidationState
	FirstPacket                                          reassembly.TimeState
	Ident, NetworkScope, RoleSource                      string
	ClientISN, ServerISN                                 uint32
	InitStage                                            uint8
	ClientDirection                                      reassembly.TCPFlowDirection
	FSMError, ResetObserved, PayloadAdmission, WasMerged bool
	Completion                                           core.StreamCompletion
	Readers                                              [2]*coldReaderState
	RetainedBytes                                        int64
	PostCloseBytes                                       [2]int
	ResourcesReleased                                    bool
}

type coldReaderState struct {
	Prefix                string
	Count                 uint64
	Bytes                 int
	Client, Saved, Closed bool
}

func readerClosed(r *tcpStreamReader) bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func canStoreReader(r streamReader) bool {
	if r == nil {
		return true
	}
	owned, ok := r.(*tcpStreamReader)
	return ok && owned.dataChan == nil && len(owned.data) == 0 && len(owned.storedMarkers) == 0 &&
		(owned.stored == nil || !owned.stored.loaded) && (owned.stored != nil || owned.numBytes == 0 || readerClosed(owned))
}

func saveReader(r streamReader) *coldReaderState {
	if r == nil {
		return nil
	}
	owned := r.(*tcpStreamReader)
	s := &coldReaderState{Bytes: owned.numBytes, Client: owned.isClient, Saved: owned.saved, Closed: readerClosed(owned)}
	if owned.stored != nil {
		s.Prefix, s.Count = owned.stored.prefix, owned.stored.count
	}
	return s
}

func (t *tcpConnection) ColdEligible() bool {
	if t.incremental != nil || t.pendingFIN[0] != nil || t.pendingFIN[1] != nil || len(t.merged) != 0 {
		return false
	}
	for _, markers := range [][2]*core.StreamData{t.retentionMarkers, t.pageBudgetMarkers, t.postCloseMarkers} {
		if markers[0] != nil || markers[1] != nil {
			return false
		}
	}
	return canStoreReader(t.client) && canStoreReader(t.server)
}

func (t *tcpConnection) SaveColdState() ([]byte, error) {
	t.Lock()
	defer t.Unlock()
	if !t.ColdEligible() || t.tcpstate == nil {
		return nil, fmt.Errorf("TCP stream has nonspillable reader state")
	}
	return json.Marshal(coldTCPState{Version: 1, Network: reassembly.SaveFlow(t.net), Transport: reassembly.SaveFlow(t.transport),
		Validation: reassembly.SaveTCPValidation(t.tcpstate, t.optchecker), FirstPacket: reassembly.SaveTime(t.firstPacket),
		Ident: t.ident, NetworkScope: t.networkScope, RoleSource: t.roleSource, ClientISN: t.clientISN, ServerISN: t.serverISN,
		InitStage: t.initStage, ClientDirection: t.clientDirection, FSMError: t.fsmerr, ResetObserved: t.resetObserved,
		PayloadAdmission: t.payloadAdmission, WasMerged: t.wasMerged, Completion: t.completion,
		Readers: [2]*coldReaderState{saveReader(t.client), saveReader(t.server)}, RetainedBytes: t.retainedPayloadBytes, PostCloseBytes: t.postCloseBytes, ResourcesReleased: t.resourcesReleased})
}

func (t *tcpConnection) ColdSuspended() {
	t.detachColdReaders()
	t.stateBudget.Release(t.stateCredit)
	t.stateCredit = 0
}

func (t *tcpConnection) detachColdReaders() {
	for _, reader := range []streamReader{t.client, t.server} {
		if owned, ok := reader.(*tcpStreamReader); ok {
			owned.CloseData()
			t.factory.Lock()
			if owned.factorySlot >= 0 && t.factory.streamReaders[owned.factorySlot] == reader {
				t.factory.streamReaders[owned.factorySlot] = nil
				t.factory.freeReaderSlots = append(t.factory.freeReaderSlots, owned.factorySlot)
				owned.factorySlot = -1
			}
			t.factory.Unlock()
		}
	}
}

func (t *tcpConnection) ColdRetired() {
	t.releaseResources()
	t.ReassemblyRetired()
}

func (f *connectionFactory) RestoreColdState(wire []byte, reserve bool) (reassembly.Stream, error) {
	var state coldTCPState
	if len(wire) > 1<<20 {
		return nil, fmt.Errorf("stored TCP control state exceeds limit")
	}
	if err := json.Unmarshal(wire, &state); err != nil {
		return nil, err
	}
	if state.Version != 1 || state.InitStage > 3 {
		return nil, fmt.Errorf("invalid stored TCP control state")
	}
	for _, reader := range state.Readers {
		if reader != nil && (reader.Bytes < 0 || reader.Prefix == "" && reader.Count != 0 || reader.Prefix != "" && (!strings.HasPrefix(reader.Prefix, "tcp/payload/") || !strings.HasSuffix(reader.Prefix, "/") || decoderconfig.Instance.AggregateStore == nil)) {
			return nil, fmt.Errorf("invalid stored TCP reader")
		}
	}
	network, err := state.Network.Restore()
	if err != nil {
		return nil, err
	}
	transport, err := state.Transport.Restore()
	if err != nil {
		return nil, err
	}
	fsm, options, err := state.Validation.Restore()
	if err != nil {
		return nil, err
	}
	first, err := state.FirstPacket.Restore()
	if err != nil {
		return nil, err
	}
	f.Lock()
	budget, payloadBudget := f.stateBudget, f.payloadBudget
	f.Unlock()
	credit := int64(0)
	if reserve {
		credit = 4096
		if err := budget.Reserve(credit); err != nil {
			f.failIncremental(err)
			return nil, err
		}
	}
	t := &tcpConnection{factory: f, net: network, transport: transport, tcpstate: fsm, optchecker: options,
		firstPacket: first, ident: state.Ident, networkScope: state.NetworkScope, roleSource: state.RoleSource,
		clientISN: state.ClientISN, serverISN: state.ServerISN, initStage: state.InitStage, clientDirection: state.ClientDirection,
		fsmerr: state.FSMError, resetObserved: state.ResetObserved, payloadAdmission: state.PayloadAdmission,
		wasMerged: state.WasMerged, completion: state.Completion, stateBudget: budget, stateCredit: credit, payloadBudget: payloadBudget}
	t.retainedPayloadBytes, t.postCloseBytes, t.resourcesReleased = state.RetainedBytes, state.PostCloseBytes, state.ResourcesReleased
	if state.ResourcesReleased {
		t.releaseOnce.Do(func() {})
	}
	for i, stored := range state.Readers {
		if stored == nil {
			continue
		}
		reader := t.newTCPStreamReader(stored.Client)
		reader.numBytes, reader.saved = stored.Bytes, stored.Saved
		if stored.Prefix != "" {
			reader.stored = &storedTCPReader{state: decoderconfig.Instance.AggregateStore, prefix: stored.Prefix, count: stored.Count, budget: budget, payloadBudget: payloadBudget}
		}
		if stored.Closed {
			reader.closeOnce.Do(func() { close(reader.done) })
		} else {
			reader.synchronousFactory = f
			f.wg.Add(1)
			f.Lock()
			slot := len(f.streamReaders)
			if last := len(f.freeReaderSlots) - 1; last >= 0 {
				slot = f.freeReaderSlots[last]
				f.freeReaderSlots = f.freeReaderSlots[:last]
			} else {
				f.streamReaders = append(f.streamReaders, nil)
			}
			f.streamReaders[slot], reader.factorySlot = reader, slot
			f.numActive++
			f.Unlock()
		}
		if i == 0 {
			t.client = reader
		} else {
			t.server = reader
		}
	}
	t.decoder = &tcpReader{parent: t}
	return t, nil
}
