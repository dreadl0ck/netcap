package firewall

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func startPolicyMaintenance(ctx context.Context, current func() *policy.Compiled, log io.Writer) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		maintainPolicies(ctx, current, log, ticker.C)
	}()
	return func() { cancel(); <-done }
}

func maintainPolicies(ctx context.Context, current func() *policy.Compiled, log io.Writer, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok || ctx.Err() != nil {
				return
			}
			if p := current(); p != nil {
				if _, err := p.Maintain(); err != nil {
					fmt.Fprintln(log, "policy maintenance failed")
				}
			}
		}
	}
}
