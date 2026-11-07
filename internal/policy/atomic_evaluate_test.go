package policy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestFailedEvaluationStagesExpiryWithAllOtherState(t *testing.T) {
	for _, mode := range []string{"fixed", "sliding", "distinct", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			r := deny("a", "true")
			r.Priority = 10
			r.Threshold = &Threshold{Count: 2, Window: "1s", GroupBy: "ClientIP", Mode: mode}
			if mode == "distinct" {
				r.Threshold.Mode, r.Threshold.Distinct = "sliding", "Attributes.value"
			}
			if mode == "sequence" {
				r.Threshold = nil
				r.Sequence = &Sequence{Name: "dns-tls", Window: "1s", GroupBy: "ClientIP", Steps: []string{`Protocol == "dns"`, `Protocol == "tls"`}}
			}
			failure := deny("z", `Method == "BAD"`)
			failure.Threshold = &Threshold{Count: 2, Window: "1s", Distinct: "Fields.required"}
			c := compiled(t, bundle(r, failure))
			ctx := context.Background()
			start := time.Unix(100, 0)
			e := Event{ClientIP: "one", Protocol: "dns", Attributes: map[string]string{"value": "a"}}
			if _, err := c.EvaluateAt(ctx, e, start); err != nil {
				t.Fatal(err)
			}
			before, err := c.ExportState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			e.Method, e.Protocol, e.Attributes["value"] = "BAD", "tls", "b"
			if _, err := c.EvaluateAt(ctx, e, start.Add(2*time.Second)); !errors.Is(err, ErrMissingStateField) {
				t.Fatal(err)
			}
			after, err := c.ExportState(ctx)
			if err != nil || !bytes.Equal(before, after) || !c.StateWatermark().Equal(start) {
				t.Fatal("failed future evaluation changed state/clock", err)
			}
			e.Method = ""
			d, err := c.EvaluateAt(ctx, e, start.Add(500*time.Millisecond))
			if err != nil || d.Verdict != "deny" {
				t.Fatal("failed expiry cleanup forgot the original live state", d, err)
			}
		})
	}
}

type cancelAtCheck struct {
	context.Context
	checks, limit int
}

func (c *cancelAtCheck) Err() error {
	c.checks++
	if c.checks >= c.limit {
		return context.Canceled
	}
	return nil
}

func TestCancellationBeforeStatelessCommitDoesNotAdvanceWatermark(t *testing.T) {
	c := compiled(t, bundle())
	start := time.Unix(100, 0)
	if _, err := c.EvaluateAt(context.Background(), Event{}, start); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAtCheck{Context: context.Background(), limit: 3}
	if _, err := c.EvaluateAt(ctx, Event{}, start.Add(time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !c.StateWatermark().Equal(start) {
		t.Fatal("stateless cancellation advanced the watermark")
	}
}
