package protocoltest

import (
	"context"
	"fmt"
)

const GenerationVersion = "protocoltest-v2"

type ExperimentMetadata struct {
	Version       int       `json:"version"`
	TargetVersion string    `json:"targetVersion"`
	Reset         ResetSpec `json:"reset"`
}
type ResetSpec struct {
	Mode        string    `json:"mode"`
	Description string    `json:"description"`
	Exchange    *Exchange `json:"exchange,omitempty"`
}
type ResetEvidence struct {
	Mode        string  `json:"mode"`
	Description string  `json:"description"`
	Observation *Result `json:"observation,omitempty"`
	Isolation   string  `json:"isolation"`
}

func (m ExperimentMetadata) Validate() error {
	if m.Version != 1 || m.TargetVersion == "" || len(m.TargetVersion) > 1024 || m.Reset.Description == "" || len(m.Reset.Description) > 4096 {
		return fmt.Errorf("experiment version 1, target version and explicit reset description required")
	}
	switch m.Reset.Mode {
	case "connection":
		if m.Reset.Exchange != nil {
			return fmt.Errorf("connection reset cannot contain reset exchange")
		}
	case "exchange":
		if m.Reset.Exchange == nil {
			return fmt.Errorf("exchange reset requires bounded reset exchange")
		}
		if err := m.Reset.Exchange.Validate(); err != nil {
			return err
		}
		asserted := false
		for _, s := range m.Reset.Exchange.Steps {
			if s.Receive && (s.ExpectPresent || len(s.Expect) > 0 || len(s.Contains) > 0) {
				asserted = true
			}
		}
		if !asserted {
			return fmt.Errorf("reset exchange must assert an acknowledgement")
		}
	default:
		return fmt.Errorf("unsupported reset mode; use declared connection isolation or asserted reset exchange; external OS resets are import-only")
	}
	return nil
}
func (m ExperimentMetadata) resetBytes() int {
	if m.Reset.Exchange != nil {
		return m.Reset.Exchange.MaxTotalBytes
	}
	return 0
}
func runIsolated(ctx context.Context, e Exchange, m ExperimentMetadata) (Result, ResetEvidence, error) {
	reset := ResetEvidence{Mode: m.Reset.Mode, Description: m.Reset.Description, Isolation: "new connection and empty variable map; target connection isolation is analyst-declared"}
	if err := m.Validate(); err != nil {
		return Result{}, reset, err
	}
	if m.Reset.Mode == "exchange" {
		r, err := Run(ctx, *m.Reset.Exchange)
		reset.Observation = &r
		if err != nil {
			reset.Isolation = "reset failed; target exchange not started"
			return Result{Version: 1, Status: "error", Error: "reset failed: " + err.Error()}, reset, fmt.Errorf("reset failed: %w", err)
		}
		reset.Isolation = "reset acknowledgement observed before fresh target connection; reset semantics are analyst-declared"
	}
	r, err := Run(ctx, e)
	return r, reset, err
}
