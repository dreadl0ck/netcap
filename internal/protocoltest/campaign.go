package protocoltest

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

type Campaign struct {
	Control       Exchange `json:"control"`
	SendStep      int      `json:"sendStep"`
	ResponseStep  int      `json:"responseStep"`
	FailureMarker []byte   `json:"failureMarker"`
	MaxCases      int      `json:"maxCases"`
	MaxAttempts   int      `json:"maxAttempts"`
}
type CampaignTrial struct {
	Input                 []byte `json:"input"`
	Result                Result `json:"result"`
	FailureMarkerReturned bool   `json:"failureMarkerReturned"`
}
type CampaignResult struct {
	Before     Result          `json:"before"`
	Trials     []CampaignTrial `json:"trials"`
	Minimized  *Minimized      `json:"minimized,omitempty"`
	After      Result          `json:"after"`
	Limitation string          `json:"limitation"`
}

// RunCampaign uses an application marker as its oracle, never a timeout or crash.
// Each trial gets a fresh connection; external state reset remains caller-owned.
func RunCampaign(ctx context.Context, spec Campaign) (out CampaignResult, runErr error) {
	out.Limitation = "byte truncation/XOR corpus; marker observation only, not crash or RCE; external state reset is caller-owned"
	if err := spec.Control.Validate(); err != nil {
		return out, err
	}
	if spec.SendStep < 0 || spec.SendStep >= len(spec.Control.Steps) || spec.ResponseStep < spec.SendStep || spec.ResponseStep >= len(spec.Control.Steps) || !spec.Control.Steps[spec.ResponseStep].Receive || spec.Control.Steps[spec.SendStep].SendVariable != "" || len(spec.FailureMarker) == 0 || len(spec.FailureMarker) > spec.Control.Framing.MaxBytes || spec.MaxAttempts < 1 || spec.MaxAttempts > 128 || spec.MaxCases < 1 || spec.MaxCases > 1024 {
		return out, fmt.Errorf("invalid campaign selectors/bounds; variable send mutation unsupported")
	}
	if int64(spec.MaxCases+spec.MaxAttempts+2)*int64(spec.Control.MaxTotalBytes) > 16<<20 {
		return out, fmt.Errorf("campaign evidence budget exceeded")
	}
	corpus, err := MutationCorpus(spec.Control.Steps[spec.SendStep].Send, spec.MaxCases, 1<<20)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	hasMarker := func(r Result) bool {
		for _, o := range r.Observations {
			if o.Step == spec.ResponseStep && o.Direction == "received" && bytes.Contains(o.Bytes, spec.FailureMarker) {
				return true
			}
		}
		return false
	}
	out.Before, err = Run(ctx, spec.Control)
	if err != nil {
		return out, fmt.Errorf("valid precontrol: %w", err)
	}
	if hasMarker(out.Before) {
		return out, fmt.Errorf("failure marker also occurs in valid control")
	}
	defer func() {
		var err error
		out.After, err = Run(ctx, spec.Control)
		if runErr == nil && (err != nil || hasMarker(out.After)) {
			runErr = fmt.Errorf("valid postcontrol failed: %v", err)
		}
	}()
	trial := func(ctx context.Context, input []byte) (bool, error) {
		e := spec.Control
		e.Steps = append([]Step(nil), e.Steps...)
		e.Steps[spec.SendStep].Send = bytes.Clone(input)
		e.Steps[spec.SendStep].SendPresent = true
		// The mutated response has a separate explicit oracle from the valid control.
		e.Steps[spec.ResponseStep].Expect = nil
		e.Steps[spec.ResponseStep].ExpectPresent = false
		e.Steps[spec.ResponseStep].Contains = nil
		r, err := Run(ctx, e)
		failed := err == nil && hasMarker(r)
		out.Trials = append(out.Trials, CampaignTrial{Input: bytes.Clone(input), Result: r, FailureMarkerReturned: failed})
		return failed, err
	}
	var failure []byte
	for _, c := range corpus[1:] {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		failed, _ := trial(ctx, c.Input)
		if failed && failure == nil {
			failure = bytes.Clone(c.Input)
		}
	}
	if failure != nil {
		r, err := Minimize(ctx, failure, spec.MaxAttempts, func(ctx context.Context, b []byte) (bool, error) {
			failed, err := trial(ctx, b)
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if err != nil {
				return false, nil
			}
			return failed, nil
		})
		out.Minimized = &r
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
