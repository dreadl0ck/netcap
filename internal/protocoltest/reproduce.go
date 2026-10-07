package protocoltest

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

type ReproductionSpec struct {
	Metadata      ExperimentMetadata `json:"metadata"`
	Case          GeneratedCase      `json:"case"`
	FailureMarker []byte             `json:"failureMarker"`
}
type ReproductionResult struct {
	Version           int              `json:"version"`
	GenerationVersion string           `json:"generationVersion"`
	Spec              ReproductionSpec `json:"spec"`
	Trial             CampaignTrial    `json:"trial"`
}

func Reproduce(ctx context.Context, spec ReproductionSpec) (ReproductionResult, error) {
	r := ReproductionResult{Version: 1, GenerationVersion: GenerationVersion, Spec: spec}
	c := spec.Case
	if err := spec.Metadata.Validate(); err != nil {
		return r, err
	}
	if err := c.Exchange.Validate(); err != nil {
		return r, err
	}
	if c.ConfigurationSHA256 != caseHash(c) || c.SendStep < 0 || c.SendStep >= len(c.Exchange.Steps) || c.ResponseStep < c.SendStep || c.ResponseStep >= len(c.Exchange.Steps) || !c.Exchange.Steps[c.ResponseStep].Receive || len(spec.FailureMarker) == 0 || len(spec.FailureMarker) > c.Exchange.Framing.MaxBytes {
		return r, fmt.Errorf("invalid reproduction case/hash/oracle")
	}
	if c.Exchange.MaxTotalBytes+spec.Metadata.resetBytes() > 16<<20 {
		return r, fmt.Errorf("reproduction evidence budget exceeded")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	result, reset, err := runIsolated(ctx, c.Exchange, spec.Metadata)
	r.Trial = CampaignTrial{Case: c, Reset: reset, Input: bytes.Clone(c.Exchange.Steps[c.SendStep].Send), Result: result}
	if err != nil {
		return r, err
	}
	for _, o := range result.Observations {
		if o.Direction == "received" && o.Step == c.ResponseStep && bytes.Contains(o.Bytes, spec.FailureMarker) {
			r.Trial.FailureMarkerReturned = true
		}
	}
	if !r.Trial.FailureMarkerReturned {
		return r, fmt.Errorf("failure marker did not reproduce")
	}
	return r, nil
}
