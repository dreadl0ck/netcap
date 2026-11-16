package tcp

import (
	"encoding/json"
	"fmt"

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
}

func (t *tcpConnection) ColdEligible() bool {
	return t.client == nil && t.server == nil && t.incremental == nil && t.pendingFIN[0] == nil && t.pendingFIN[1] == nil && t.retainedPayloadBytes == 0
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
		PayloadAdmission: t.payloadAdmission, WasMerged: t.wasMerged, Completion: t.completion})
}

func (t *tcpConnection) ColdSuspended() {
	t.stateBudget.Release(t.stateCredit)
	t.stateCredit = 0
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
	t.decoder = &tcpReader{parent: t}
	return t, nil
}
