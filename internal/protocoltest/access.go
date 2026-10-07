package protocoltest

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

type AccessCase struct {
	ResponseStep int      `json:"responseStep"`
	Role         string   `json:"role"`
	State        string   `json:"state"`
	Resource     string   `json:"resource"`
	Message      string   `json:"message"`
	Allowed      bool     `json:"allowed"`
	Marker       []byte   `json:"marker"`
	Exchange     Exchange `json:"exchange"`
}
type AccessObservation struct {
	Case           AccessCase `json:"case"`
	Result         Result     `json:"result"`
	MarkerReturned bool       `json:"markerReturned"`
	Status         string     `json:"status"`
}

// RunAccess opens a fresh session per case. Absence is meaningful only after
// the case's response assertions matched; failures remain inconclusive.
func RunAccess(ctx context.Context, cases []AccessCase) ([]AccessObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if len(cases) < 1 || len(cases) > 64 {
		return nil, fmt.Errorf("access matrix requires 1..64 cases")
	}
	total := 0
	for _, c := range cases {
		if c.Role == "" || c.State == "" || c.Resource == "" || c.Message == "" || len(c.Marker) == 0 {
			return nil, fmt.Errorf("matrix labels and resource marker required")
		}
		if err := c.Exchange.Validate(); err != nil {
			return nil, err
		}
		if c.ResponseStep < 0 || c.ResponseStep >= len(c.Exchange.Steps) || !c.Exchange.Steps[c.ResponseStep].Receive || len(c.Marker) > c.Exchange.Framing.MaxBytes {
			return nil, fmt.Errorf("resource response step and bounded marker required")
		}
		total += c.Exchange.MaxTotalBytes
		if total > 16<<20 {
			return nil, fmt.Errorf("matrix evidence budget exceeded")
		}
	}
	out := []AccessObservation{}
	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		r, err := Run(ctx, c.Exchange)
		o := AccessObservation{Case: c, Result: r, Status: "inconclusive"}
		for _, v := range r.Observations {
			if v.Step == c.ResponseStep && v.Direction == "received" && bytes.Contains(v.Bytes, c.Marker) {
				o.MarkerReturned = true
			}
		}
		if err == nil {
			o.Status = "matched"
			if o.MarkerReturned != c.Allowed {
				o.Status = "boundary-mismatch"
			}
		}
		out = append(out, o)
	}
	return out, nil
}
