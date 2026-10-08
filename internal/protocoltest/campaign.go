package protocoltest

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

type Campaign struct {
	Metadata      ExperimentMetadata `json:"metadata"`
	Generation    *GenerationSpec    `json:"generation,omitempty"`
	Control       Exchange           `json:"control"`
	SendStep      int                `json:"sendStep"`
	ResponseStep  int                `json:"responseStep"`
	FailureMarker []byte             `json:"failureMarker"`
	MaxCases      int                `json:"maxCases"`
	MaxAttempts   int                `json:"maxAttempts"`
}
type CampaignTrial struct {
	Case                  GeneratedCase `json:"case"`
	Reset                 ResetEvidence `json:"reset"`
	Input                 []byte        `json:"input"`
	Result                Result        `json:"result"`
	FailureMarkerReturned bool          `json:"failureMarkerReturned"`
}
type CampaignResult struct {
	MinimizationMethod   string          `json:"minimizationMethod,omitempty"`
	MinimizationComplete bool            `json:"minimizationComplete"`
	Corpus               GeneratedCorpus `json:"corpus"`
	BeforeReset          ResetEvidence   `json:"beforeReset"`
	AfterReset           ResetEvidence   `json:"afterReset"`
	MinimizedCase        *GeneratedCase  `json:"minimizedCase,omitempty"`
	Reproduction         *CampaignTrial  `json:"reproduction,omitempty"`
	Before               Result          `json:"before"`
	Trials               []CampaignTrial `json:"trials"`
	Minimized            *Minimized      `json:"minimized,omitempty"`
	After                Result          `json:"after"`
	Limitation           string          `json:"limitation"`
}

// RunCampaign uses an application marker as its oracle, never a timeout or crash.
// Each trial gets a fresh connection and its declared reset; OS resets are import-only.
func RunCampaign(ctx context.Context, spec Campaign) (out CampaignResult, runErr error) {
	if err := spec.Metadata.Validate(); err != nil {
		return out, err
	}
	out.Limitation = "deterministic bounded byte/field/setup-step mutations; minimizes first marker-positive case only; marker observation is not crash or RCE; reset acknowledgement does not prove OS-wide isolation"
	if err := spec.Control.Validate(); err != nil {
		return out, err
	}
	if spec.SendStep < 0 || spec.SendStep >= len(spec.Control.Steps) || spec.ResponseStep < spec.SendStep || spec.ResponseStep >= len(spec.Control.Steps) || !spec.Control.Steps[spec.ResponseStep].Receive || spec.Control.Steps[spec.SendStep].SendVariable != "" || len(spec.FailureMarker) == 0 || len(spec.FailureMarker) > spec.Control.Framing.MaxBytes || spec.MaxAttempts < 1 || spec.MaxAttempts > 128 || spec.MaxCases < 1 || spec.MaxCases > 1024 {
		return out, fmt.Errorf("invalid campaign selectors/bounds; variable send mutation unsupported")
	}
	if int64(spec.MaxCases+spec.MaxAttempts+3)*int64(spec.Control.MaxTotalBytes+spec.Metadata.resetBytes()) > 16<<20 {
		return out, fmt.Errorf("campaign evidence budget exceeded")
	}
	corpus, err := GenerateCampaign(spec)
	out.Corpus = corpus
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	hasMarker := func(r Result, response int) bool {
		for _, o := range r.Observations {
			if o.Step == response && o.Direction == "received" && bytes.Contains(o.Bytes, spec.FailureMarker) {
				return true
			}
		}
		return false
	}
	control := corpus.Cases[0]
	out.Before, out.BeforeReset, err = runIsolated(ctx, control.Exchange, spec.Metadata)
	if err != nil {
		return out, fmt.Errorf("valid precontrol: %w", err)
	}
	if hasMarker(out.Before, control.ResponseStep) {
		return out, fmt.Errorf("failure marker also occurs in valid control")
	}
	defer func() {
		var err error
		out.After, out.AfterReset, err = runIsolated(ctx, control.Exchange, spec.Metadata)
		if err != nil || hasMarker(out.After, control.ResponseStep) {
			out.MinimizationComplete = false
			if runErr == nil {
				runErr = fmt.Errorf("valid postcontrol failed: %v", err)
			}
		}
	}()
	trial := func(ctx context.Context, c GeneratedCase) (bool, error) {
		c.ConfigurationSHA256 = caseHash(c)
		r, reset, err := runIsolated(ctx, c.Exchange, spec.Metadata)
		failed := err == nil && hasMarker(r, c.ResponseStep)
		out.Trials = append(out.Trials, CampaignTrial{Case: c, Reset: reset, Input: bytes.Clone(c.Exchange.Steps[c.SendStep].Send), Result: r, FailureMarkerReturned: failed})
		return failed, err
	}
	var failure *GeneratedCase
	for _, c := range corpus.Cases[1:] {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		failed, trialErr := trial(ctx, c)
		if trialErr != nil && out.Trials[len(out.Trials)-1].Reset.Observation != nil && out.Trials[len(out.Trials)-1].Reset.Observation.Status != "matched" {
			return out, trialErr
		}
		if failed && failure == nil {
			copy := c
			failure = &copy
		}
	}
	if failure != nil {
		best := *failure
		if best.Kind == "state" {
			out.MinimizationMethod = "setup-step deletion; target send/response retained"
			attempts := 0
			for i := 0; i < best.SendStep; {
				if attempts >= spec.MaxAttempts {
					return out, fmt.Errorf("state minimization attempt budget exceeded")
				}
				attempts++
				candidate := best
				candidate.Exchange.Steps = append([]Step(nil), best.Exchange.Steps...)
				candidate.Exchange.Steps = append(candidate.Exchange.Steps[:i], candidate.Exchange.Steps[i+1:]...)
				candidate.SendStep--
				candidate.ResponseStep--
				failed, err := trial(ctx, candidate)
				if ctx.Err() != nil {
					return out, ctx.Err()
				}
				if err != nil {
					return out, fmt.Errorf("state minimization inconclusive: %w", err)
				}
				if failed {
					best = candidate
					i = 0
				} else {
					i++
				}
			}
		} else if best.Kind == "field" {
			out.MinimizationMethod = "changed-byte restoration to control; fixed field widths retained"
			baseline := control.Exchange.Steps[control.SendStep].Send
			input := bytes.Clone(best.Exchange.Steps[best.SendStep].Send)
			r := Minimized{Original: bytes.Clone(input), Input: input}
			out.Minimized = &r
			for i := 0; i < len(input); {
				if input[i] == baseline[i] {
					i++
					continue
				}
				if r.Attempts >= spec.MaxAttempts {
					return out, fmt.Errorf("field minimization attempt budget exceeded")
				}
				r.Attempts++
				candidate := best
				candidate.Exchange.Steps = append([]Step(nil), best.Exchange.Steps...)
				data := bytes.Clone(input)
				data[i] = baseline[i]
				candidate.Exchange.Steps[candidate.SendStep].Send = data
				failed, err := trial(ctx, candidate)
				if err != nil {
					return out, fmt.Errorf("field minimization inconclusive: %w", err)
				}
				if failed {
					input = data
					best = candidate
					r.Input = bytes.Clone(input)
					i = 0
				} else {
					i++
				}
			}
			r.Complete = true
		} else {
			out.MinimizationMethod = "byte deletion; dependent lengths are not repaired"
			r, err := Minimize(ctx, best.Exchange.Steps[best.SendStep].Send, spec.MaxAttempts, func(ctx context.Context, b []byte) (bool, error) {
				candidate := best
				candidate.Exchange.Steps = append([]Step(nil), best.Exchange.Steps...)
				candidate.Exchange.Steps[candidate.SendStep].Send = bytes.Clone(b)
				candidate.Exchange.Steps[candidate.SendStep].SendPresent = true
				failed, err := trial(ctx, candidate)
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				return failed, err
			})
			out.Minimized = &r
			if err != nil {
				return out, err
			}
			best.Exchange.Steps = append([]Step(nil), best.Exchange.Steps...)
			best.Exchange.Steps[best.SendStep].Send = bytes.Clone(r.Input)
			best.Exchange.Steps[best.SendStep].SendPresent = true
		}
		best.ID = "minimized-" + best.ID
		best.ConfigurationSHA256 = caseHash(best)
		out.MinimizedCase = &best
		failed, err := trial(ctx, best)
		copy := out.Trials[len(out.Trials)-1]
		out.Reproduction = &copy
		if err != nil {
			return out, err
		}
		if !failed {
			return out, fmt.Errorf("minimized case failed independent reproduction")
		}
		out.MinimizationComplete = true
	}
	return out, nil
}
