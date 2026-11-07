package policystate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

const EvaluatePath = "/api/v1/policy-state/evaluate"
const HealthPath = "/api/v1/policy-state/health"

// decode retains dynamic map keys, but all struct keys are exact/case-sensitive.
// Raw policy artifacts use policy.Parse's own stricter JSON/YAML validation.
func decode(raw []byte, dst any) error {
	if err := firewallstate.Decode(raw, dst); err != nil {
		return err
	}
	return exactKeys(raw, reflect.TypeOf(dst).Elem())
}

func exactKeys(raw []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t == reflect.TypeOf(json.RawMessage{}) || t == reflect.TypeOf(time.Time{}) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		for key, value := range object {
			found := false
			for i := 0; i < t.NumField(); i++ {
				field := t.Field(i)
				if strings.Split(field.Tag.Get("json"), ",")[0] == key {
					found = true
					if err := exactKeys(value, field.Type); err != nil {
						return err
					}
					break
				}
			}
			if !found {
				return errors.New("unknown or incorrectly cased field")
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		for _, value := range object {
			if err := exactKeys(value, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactKeys(value, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

type health struct {
	Version int  `json:"version"`
	Ready   bool `json:"ready"`
}

func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Auth != nil && strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			s.cfg.Auth.LifecycleHandler(s.cfg.Origin).ServeHTTP(w, r)
			return
		}
		var principal *Principal
		for i := range s.cfg.Principals {
			if firewallstate.MatchToken(firewallstate.Bearer(r), s.cfg.Principals[i].Token) {
				principal = &s.cfg.Principals[i]
			}
		}
		if s.cfg.Auth != nil {
			identity, err := s.cfg.Auth.Authenticate(r.Context(), firewallstate.Bearer(r))
			if err != nil {
				firewallstate.WriteError(w, firewallstate.Fail(401, "credential rejected"))
				return
			}
			action := firewallauth.Evaluate
			if r.URL.Path == HealthPath {
				action = firewallauth.Read
			}
			scope, err := identity.BoundScope(action, s.cfg.Environment, s.cfg.Target)
			if err != nil {
				firewallstate.WriteError(w, firewallstate.Fail(403, "state grant required"))
				return
			}
			principal = &Principal{ID: identity.ID, Scope: firewallstate.Scope{Tenant: scope.Tenant, App: scope.App}}
			r = r.WithContext(firewallauth.WithPrincipal(r.Context(), identity))
		}
		if principal == nil {
			firewallstate.WriteError(w, firewallstate.Fail(401, "unauthorized"))
			return
		}
		if !firewallauth.AllowOrigin(r, s.cfg.Origin) {
			firewallstate.WriteError(w, firewallstate.Fail(403, "origin refused"))
			return
		}
		if r.URL.Path == "/metrics" && r.Method == http.MethodGet {
			s.Operations.Handler().ServeHTTP(w, r)
			return
		}
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			firewallstate.WriteError(w, firewallstate.Fail(503, "native policy state busy"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if r.URL.Path == HealthPath && r.Method == http.MethodGet {
			if err := s.Ready(ctx); err != nil {
				firewallstate.WriteError(w, err)
				return
			}
			firewallstate.WriteJSON(w, 200, health{1, true})
			return
		}
		if r.URL.Path != EvaluatePath || r.Method != http.MethodPost {
			firewallstate.WriteError(w, firewallstate.Fail(404, "unknown native policy-state route"))
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			firewallstate.WriteError(w, firewallstate.Fail(413, "evaluation input exceeds limit"))
			return
		}
		var req Request
		if err = decode(raw, &req); err != nil {
			firewallstate.WriteError(w, firewallstate.Fail(400, "invalid evaluation schema"))
			return
		}
		d, err := s.Evaluate(ctx, principal.Scope, req)
		if err != nil {
			firewallstate.WriteError(w, err)
			return
		}
		firewallstate.WriteJSON(w, 200, d)
	})
}
