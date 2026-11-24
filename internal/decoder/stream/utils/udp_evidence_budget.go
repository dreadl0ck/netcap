package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const UDPStreamEvidenceCoverageFile = "udp-stream-evidence.json"

const (
	maxUDPStreamFlows = 4096
	maxUDPStreamFlowBytes = 1 << 20
	maxUDPStreamCharge = 64 << 20
)

type udpEvidenceCoverage struct {
	Flows int `json:"admittedFlows"`
	Charge int64 `json:"admittedBytesIncludingMetadata"`
	Omitted int `json:"omittedFlows"`
	OmittedBytes int64 `json:"omittedPayloadBytes"`
}

var udpEvidenceBudget struct {
	sync.Mutex
	udpEvidenceCoverage
}

func admitUDPStreamEvidence(size int64, fragments int) bool {
	// Charge both payload copies, bounded span metadata, and space per flow.
	charge := size*2+int64(fragments)*512+4096
	b := &udpEvidenceBudget
	b.Lock()
	defer b.Unlock()
	if size > maxUDPStreamFlowBytes || b.Flows >= maxUDPStreamFlows || charge > maxUDPStreamCharge-b.Charge {
		b.Omitted++
		b.OmittedBytes += size
		return false
	}
	b.Flows++
	b.Charge += charge
	return true
}

func WriteUDPStreamEvidenceCoverage(out string) error {
	udpEvidenceBudget.Lock()
	state := udpEvidenceBudget.udpEvidenceCoverage
	udpEvidenceBudget.Unlock()
	if state.Flows == 0 && state.Omitted == 0 || out == "" {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, UDPStreamEvidenceCoverageFile), data, 0600)
}
