package waf

import "errors"

type readinessHook struct{ check func() bool }

// SetReadinessCheck installs one bootstrap-only cached dependency check. The
// callback must be concurrency-safe and must not perform network health probes.
// It is ANDed with policy availability, draining and lifetime state.
func (f *Firewall) SetReadinessCheck(check func() bool) error {
	if check == nil {
		return errors.New("WAF readiness check must not be nil")
	}
	f.bootstrap.Lock()
	defer f.bootstrap.Unlock()
	if f.started || f.readiness.Load() != nil || f.lifetime.Err() != nil {
		return errors.New("WAF readiness check must be installed once before serving")
	}
	f.readiness.Store(&readinessHook{check: check})
	return nil
}

func (f *Firewall) ready() bool {
	if f.draining.Load() || f.lifetime.Err() != nil || f.Policy() == nil {
		f.Operations.Health(false, "draining")
		return false
	}
	if hook := f.readiness.Load(); hook != nil {
		ready := hook.check()
		condition := "ok"
		if !ready {
			condition = "state_unavailable"
		}
		f.Operations.Health(ready, condition)
		return ready
	}
	f.Operations.Health(true, "ok")
	return true
}
