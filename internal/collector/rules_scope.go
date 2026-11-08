package collector

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/types"
)

func (c *Collector) evaluateObservedRules(record types.AuditRecord, scope string) (int, error) {
	if !c.rulesEngine.CaptureTimeEnabled() {
		return c.rulesEngine.Evaluate(record)
	}
	if !c.rulesEngine.AppliesTo(record) {
		return 0, nil
	}
	if scope == "" {
		var err error
		scope, err = c.ruleRecordScope(record)
		if err != nil {
			return 0, err
		}
	} else {
		scope = fmt.Sprintf("%x", sha256.Sum256([]byte(scope)))
	}
	return c.rulesEngine.EvaluateObserved(scope, record)
}

func (c *Collector) ruleRecordScope(record types.AuditRecord) (string, error) {
	v := reflect.ValueOf(record)
	if v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
		if v.Kind() == reflect.Struct {
			if f := v.FieldByName("NetworkScope"); f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
				return fmt.Sprintf("%x", sha256.Sum256([]byte(f.String()))), nil
			}
			if f := v.FieldByName("Context"); f.IsValid() && f.CanInterface() {
				if ctx, ok := f.Interface().(*types.PacketContext); ok && ctx != nil && ctx.NetworkScope != "" {
					return fmt.Sprintf("%x", sha256.Sum256([]byte(ctx.NetworkScope))), nil
				}
			}
		}
	}
	c.analysisMu.Lock()
	defer c.analysisMu.Unlock()
	var bound recordScope
	var ok bool
	if r, has := record.(interface {
		GetSrcIP() string
		GetDstIP() string
		GetSrcPort() int32
		GetDstPort() int32
	}); has {
		bound, ok = c.recordScopes[endpoints(r.GetSrcIP(), r.GetSrcPort(), r.GetDstIP(), r.GetDstPort())]
	}
	if r, is := record.(*types.Secret); is {
		if a, p, b, q, valid := secret.SecretEndpoints(r.Flow); valid {
			bound, ok = c.recordScopes[endpoints(a, p, b, q)]
		}
	}
	if !ok || bound.Ambiguous || bound.NetworkScope == "" {
		return "", errors.New("capture-time rules require unambiguous observed record scope")
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(bound.NetworkScope))), nil
}

func (c *Collector) finalizeRules() {
	if c.rulesEngine == nil {
		return
	}
	n, err := c.rulesEngine.Finalize()
	atomic.AddInt64(&c.alertCount, int64(n))
	c.rulesErrorMu.Lock()
	err = errors.Join(c.rulesError, err)
	c.rulesErrorMu.Unlock()
	if err != nil {
		c.captureEvidenceError = errors.Join(c.captureEvidenceError, fmt.Errorf("finalize rules: %w", err))
	}
}
