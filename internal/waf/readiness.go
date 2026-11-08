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
	if f.attachment != nil {
		f.attachment.readiness.Store(f.readiness.Load())
	}
	return nil
}

func (f *Firewall) ready() bool {
	if !f.dataReady() {
		f.Operations.Health(false, "draining")
		return false
	}
	if hook := f.readiness.Load(); hook != nil && !hook.check() {
		f.Operations.Health(false, "state_unavailable")
		return false
	}
	if f.router != nil {
		f.routeMu.Lock()
		defer f.routeMu.Unlock()
		for _, b := range f.router.current.Load().bindings {
			if !b.firewall.dataReady() {
				f.Operations.Health(false, "state_unavailable")
				return false
			}
		}
	}
	f.Operations.Health(true, "ok")
	return true
}

func (f *Firewall) dataReady() bool {
	if f.draining.Load() || f.lifetime.Err() != nil || f.Policy() == nil {
		return false
	}
	var hook *readinessHook
	if f.attachment != nil {
		if f.attachment.draining.Load() {
			return false
		}
		hook = f.attachment.readiness.Load()
	}
	return hook == nil || hook.check()
}
