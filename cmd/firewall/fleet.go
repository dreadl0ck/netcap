package firewall

import (
	"context"
	"errors"

	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/urfave/cli/v3"
)

func (r *runtimeEvaluator) startAgent(ctx context.Context, c *cli.Command, target firewallfleet.Target, drain func(bool), errs chan<- error) (func(), error) {
	path := c.String("fleet-agent-config")
	if path == "" {
		return func() {}, nil
	}
	cfg, closeTransport, err := agentConfig(path, r.broker != nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r.fleetUnready.Store(true)
	if drain != nil {
		drain(true)
	}
	cfg.OnStatus = func(s firewallfleet.AgentStatus) {
		unready := !s.Ready || s.Draining || s.Revoked || ctx.Err() != nil
		r.fleetUnready.Store(unready)
		r.agentStatus.Store(&s)
		if drain != nil {
			drain(unready)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := firewallfleet.Run(ctx, cfg, target)
		r.fleetUnready.Store(true)
		if drain != nil {
			drain(true)
		}
		if err != nil && ctx.Err() == nil {
			errs <- err
		}
	}()
	return func() { cancel(); <-done; closeTransport() }, nil
}

func (r *runtimeEvaluator) runWithAgent(ctx context.Context, c *cli.Command, run func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopMaintenance := startPolicyMaintenance(ctx, r.Policy, c.Root().ErrWriter)
	defer stopMaintenance()
	r.startProbes(ctx)
	errs := make(chan error, 1)
	stop, err := r.startAgent(ctx, c, r, nil, errs)
	if err != nil {
		return err
	}
	defer stop()
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	select {
	case err = <-done:
		return err
	case err = <-errs:
		cancel()
		return errors.Join(err, <-done)
	case <-ctx.Done():
		cancel()
		return <-done
	}
}
