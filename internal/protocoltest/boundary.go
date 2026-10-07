package protocoltest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// BoundaryCase uses exact application replies as the target oracle. Verification
// is a readback after the probe without resetting its effects first.
type BoundaryCase struct {
	Metadata     ExperimentMetadata `json:"metadata"`
	Name         string             `json:"name"`
	Control      Exchange           `json:"control"`
	Probe        Exchange           `json:"probe"`
	ResponseStep int                `json:"responseStep"`
	Accepted     []byte             `json:"accepted"`
	Rejected     []byte             `json:"rejected"`
	Verification *Exchange          `json:"verification,omitempty"`
}
type BoundaryResult struct {
	Version             int           `json:"version"`
	GenerationVersion   string        `json:"generationVersion"`
	Case                BoundaryCase  `json:"case"`
	ConfigurationSHA256 string        `json:"configurationSHA256"`
	Outcome             string        `json:"outcome"`
	Before              Result        `json:"before"`
	BeforeReset         ResetEvidence `json:"beforeReset"`
	Probe               Result        `json:"probe"`
	ProbeReset          ResetEvidence `json:"probeReset"`
	Verification        *Result       `json:"verification,omitempty"`
	After               Result        `json:"after"`
	AfterReset          ResetEvidence `json:"afterReset"`
	Qualified           bool          `json:"qualified"`
}

func harnessOutcome(ctx context.Context, err error) string {
	if errors.Is(err, ErrBudgetExceeded) {
		return "harness-budget-stop"
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return "harness-canceled"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "harness-timeout"
	}
	return "transport-or-framing-error"
}
func RunBoundary(ctx context.Context, spec BoundaryCase) (out BoundaryResult, runErr error) {
	out = BoundaryResult{Version: 1, GenerationVersion: GenerationVersion, Case: spec, ConfigurationSHA256: configHash(spec), Outcome: "invalid-configuration"}
	if err := spec.Metadata.Validate(); err != nil {
		return out, err
	}
	if err := spec.Control.Validate(); err != nil {
		return out, err
	}
	if err := spec.Probe.Validate(); err != nil {
		return out, err
	}
	if spec.Name == "" || spec.ResponseStep < 0 || spec.ResponseStep >= len(spec.Probe.Steps) || !spec.Probe.Steps[spec.ResponseStep].Receive || len(spec.Accepted) == 0 || len(spec.Rejected) == 0 || bytes.Equal(spec.Accepted, spec.Rejected) {
		return out, fmt.Errorf("boundary name, response selector and distinct nonempty exact replies required")
	}
	selected := spec.Probe.Steps[spec.ResponseStep]
	if selected.ExpectPresent || len(selected.Expect) > 0 || len(selected.Contains) > 0 {
		return out, fmt.Errorf("probe selected response must use boundary oracle, not step assertions")
	}
	asserted := false
	for _, step := range spec.Control.Steps {
		if step.Receive && (step.ExpectPresent || len(step.Expect) > 0 || len(step.Contains) > 0) {
			asserted = true
		}
	}
	if !asserted {
		return out, fmt.Errorf("valid control needs a response assertion")
	}
	budget := 2*spec.Control.MaxTotalBytes + spec.Probe.MaxTotalBytes + 3*spec.Metadata.resetBytes()
	if spec.Verification != nil {
		if err := spec.Verification.Validate(); err != nil {
			return out, err
		}
		asserted = false
		for _, step := range spec.Verification.Steps {
			if step.Receive && (step.ExpectPresent || len(step.Expect) > 0 || len(step.Contains) > 0) {
				asserted = true
			}
		}
		if !asserted {
			return out, fmt.Errorf("effect verification needs a response assertion")
		}
		budget += spec.Verification.MaxTotalBytes
	}
	if budget > 16<<20 || len(spec.Accepted) > 65536 || len(spec.Rejected) > 65536 {
		return out, fmt.Errorf("boundary evidence limits exceeded")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out.Before, out.BeforeReset, runErr = runIsolated(ctx, spec.Control, spec.Metadata)
	if runErr != nil {
		out.Outcome = "control-failed"
		return out, runErr
	}
	defer func() {
		var err error
		out.After, out.AfterReset, err = runIsolated(ctx, spec.Control, spec.Metadata)
		if err != nil {
			out.Qualified = false
			if runErr == nil {
				runErr = fmt.Errorf("postcontrol failed: %w", err)
			}
		}
	}()
	out.Probe, out.ProbeReset, runErr = runIsolated(ctx, spec.Probe, spec.Metadata)
	if runErr != nil {
		out.Outcome = harnessOutcome(ctx, runErr)
		if out.ProbeReset.Observation != nil && out.ProbeReset.Observation.Status != "matched" {
			out.Outcome = "reset-failed"
		}
		return out, runErr
	}
	out.Outcome = "unexpected-response"
	for _, o := range out.Probe.Observations {
		if o.Direction == "received" && o.Step == spec.ResponseStep {
			if bytes.Equal(o.Bytes, spec.Accepted) {
				out.Outcome = "target-accepted"
			} else if bytes.Equal(o.Bytes, spec.Rejected) {
				out.Outcome = "target-rejected"
			}
		}
	}
	if spec.Verification != nil {
		r, err := Run(ctx, *spec.Verification)
		out.Verification = &r
		if err != nil {
			return out, fmt.Errorf("effect verification failed: %w", err)
		}
	}
	out.Qualified = out.Outcome == "target-accepted" || out.Outcome == "target-rejected"
	return out, nil
}
