package waf

import (
	"context"
	"errors"

	"github.com/dreadl0ck/netcap/internal/policy"
)

type evaluatorHook struct {
	evaluate func(context.Context, *policy.Compiled, policy.Event) (policy.Decision, error)
}

// SetEvaluator installs a bootstrap-only hook. The hook must preserve the supplied
// revision and keep broker delivery errors separate from policy evaluation errors.
// It receives every native event, including message metadata and trailers.
// An enforcing deny keeps its status even if the hook also returns an error.
func (f *Firewall) SetEvaluator(evaluate func(context.Context, *policy.Compiled, policy.Event) (policy.Decision, error)) error {
	if evaluate == nil {
		return errors.New("WAF evaluator must not be nil")
	}
	f.bootstrap.Lock()
	defer f.bootstrap.Unlock()
	if f.started || f.evaluator.Load() != nil || f.lifetime.Err() != nil {
		return errors.New("WAF evaluator must be installed once before serving")
	}
	f.evaluator.Store(&evaluatorHook{evaluate: evaluate})
	return nil
}

func (f *Firewall) startServing() {
	f.bootstrap.Lock()
	f.started = true
	f.bootstrap.Unlock()
}
