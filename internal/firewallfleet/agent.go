package firewallfleet

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type AgentConfig struct {
	URL            string
	Token          string
	TargetID       string
	Scope          Scope
	StateDir       string
	PollInterval   time.Duration
	RequestTimeout time.Duration
	AllowEffects   bool
	// MaxStale=0 retains last-known policy indefinitely. A positive value makes
	// readiness false after that outage; the caller must drain on Ready=false.
	MaxStale  time.Duration
	Transport http.RoundTripper
	OnStatus  func(AgentStatus)
}
type AgentStatus struct {
	Ready       bool
	Generation  int64
	Revision    string
	LastContact time.Time
	Error       string
	Draining    bool
	Revoked     bool
}
type cacheRecord struct {
	Binding string    `json:"binding"`
	Desired Desired   `json:"desired"`
	Contact time.Time `json:"contact"`
	MAC     string    `json:"mac"`
}

// Run owns Target.SetPolicy exclusively. SetPolicy must atomically publish the
// immutable compiled pointer; Policy/Evaluate may be concurrent. Polling is
// bounded; one joined watchdog independently expires MaxStale readiness. Run returns only on configuration,
// persistence initialization, or context cancellation; outages are status events.
// A cold agent does not trust the target's initial Policy as initialized.
// Cancellation is checked at application/publication decisions; cancellation
// after a check can race that external call. Shutdown publishes unready before
// joining the watchdog, including when cancellation occurs between polls.
func Run(ctx context.Context, cfg AgentConfig, target Target) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := firewallstate.Endpoint(cfg.URL)
	if err != nil {
		return err
	}
	if target == nil || len(cfg.Token) < 16 || !firewallstate.ValidID(cfg.TargetID) || !cfg.Scope.Valid() || cfg.MaxStale < 0 {
		return errors.New("invalid agent configuration")
	}
	if cfg.OnStatus == nil {
		return errors.New("agent requires OnStatus readiness/drain callback")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.PollInterval < 10*time.Millisecond || cfg.PollInterval > time.Minute {
		return errors.New("poll interval must be 10ms..1m")
	}
	// Use a separate local lock so two agents cannot race identity/cache state.
	if err := ctx.Err(); err != nil {
		return err
	}
	disk, err := firewallstate.OpenDatabase(cfg.StateDir, "agent")
	if err != nil {
		return err
	}
	defer disk.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	client := firewallstate.HTTPClient(cfg.RequestTimeout, cfg.Transport)
	defer client.CloseIdleConnections()
	binding := agentBinding(cfg)
	path := filepath.Join(cfg.StateDir, "agent-cache.json")
	publisher := newAgentPublisher(ctx, cfg)
	defer publisher.close()
	status := AgentStatus{}
	var lastContact time.Time
	var current Desired
	persistenceOK := true
	emit := func(e error) {
		status.Error = ""
		if e != nil {
			status.Error = e.Error()
		}
		status.Draining = current.Draining
		status.Revoked = current.Revoked
		publisher.publish(status, persistenceOK, lastContact)
	}
	if _, err = os.Lstat(path); err == nil {
		if err = firewallstate.PrivateFile(path); err != nil {
			return err
		}
		info, e := os.Stat(path)
		if e != nil {
			return e
		}
		if info.Size() > 2*MaxArtifactBytes {
			return errors.New("agent cache exceeds limit")
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var record cacheRecord
		if e = firewallstate.Decode(raw, &record); e == nil && record.Binding == binding && validMAC(record, cfg.Token) {
			c, _, verify := verifyDesired(record.Desired, cfg)
			if verify == nil && !record.Contact.IsZero() && !record.Contact.After(time.Now().Add(time.Minute)) {
				current = record.Desired
				if c != nil {
					if err := ctx.Err(); err != nil {
						return err
					}
					target.SetPolicy(c)
				}
				status.Generation = current.Generation
				status.Revision = current.Revision
				status.LastContact = record.Contact
				lastContact = record.Contact
			} else {
				err = errors.New("invalid cached policy")
			}
		} else {
			err = errors.New("cache integrity or target identity mismatch")
		}
		// Corrupt/foreign cache is never applied. Remain cold and recover online.
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		err = nil
	}
	emit(err)
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var desired Desired
		err = firewallstate.RequestJSON(ctx, client, "GET", strings.TrimSuffix(u.String(), "/")+"/api/v1/fleet/desired", cfg.Token, nil, &desired, 2*MaxArtifactBytes)
		if err == nil {
			c, _, e := verifyDesired(desired, cfg)
			err = e
			if err == nil && (desired.Generation < current.Generation || desired.Generation == current.Generation && current.Generation > 0 && (desired.Revision != current.Revision || desired.Hash != current.Hash || desired.Draining != current.Draining || desired.Revoked != current.Revoked)) {
				err = errors.New("controller generation regression or revision equivocation")
			}
			if err == nil && desired.Generation > current.Generation && !desired.Deadline.IsZero() && time.Now().After(desired.Deadline) {
				err = errors.New("desired activation deadline expired; retaining last-known policy")
			}
			if err == nil {
				if desired.Generation > current.Generation {
					if c != nil {
						if err := ctx.Err(); err != nil {
							return err
						}
						target.SetPolicy(c)
					}
					current = desired
					status.Generation = current.Generation
					status.Revision = current.Revision
				}
				// Apply before persistence and acknowledgment. Persistence failure
				// never acknowledges a revision that cannot recover after restart.
				contact := time.Now()
				record := cacheRecord{Binding: binding, Desired: desired, Contact: contact.UTC()}
				record.MAC = signCache(record, cfg.Token)
				if err := ctx.Err(); err != nil {
					return err
				}
				err = writeCache(path, record)
				persistenceOK = err == nil
				if err == nil {
					status.LastContact = contact.UTC()
					lastContact = contact
					emit(nil)
					var accepted struct {
						Accepted bool `json:"accepted"`
					}
					err = firewallstate.RequestJSON(ctx, client, "POST", strings.TrimSuffix(u.String(), "/")+"/api/v1/fleet/ack", cfg.Token, Ack{Revision: current.Revision, Generation: current.Generation, Draining: current.Draining, Revoked: current.Revoked}, &accepted, 2048)
					if err == nil && !accepted.Accepted {
						err = errors.New("ack not accepted")
					}
				}
			}
		}
		emit(err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func verifyDesired(d Desired, cfg AgentConfig) (*policy.Compiled, []byte, error) {
	if d.Version != 1 || d.TargetID != cfg.TargetID || d.Scope != cfg.Scope || d.Generation < 1 || len(d.Bundle) > MaxArtifactBytes || d.Revoked && !d.Draining {
		return nil, nil, errors.New("invalid desired identity, version, generation or hash")
	}
	if d.Draining {
		if len(d.Bundle) != 0 || d.Hash != "" || len(d.Revision) != 0 && len(d.Revision) != 64 {
			return nil, nil, errors.New("invalid draining envelope")
		}
		return nil, nil, nil
	}
	if firewallstate.Digest(string(d.Bundle)) != d.Hash {
		return nil, nil, errors.New("invalid desired bundle hash")
	}
	c, raw, err := compileAdmitted(d.Bundle, cfg.AllowEffects)
	if err != nil {
		return nil, nil, err
	}
	if c.Revision() != d.Revision || string(raw) != string(d.Bundle) {
		return nil, nil, errors.New("bundle revision/canonical mismatch")
	}
	return c, raw, nil
}

func agentBinding(cfg AgentConfig) string {
	return firewallstate.Digest(strings.TrimSuffix(cfg.URL, "/") + "\x00" + cfg.TargetID + "\x00" + cfg.Scope.Tenant + "\x00" + cfg.Scope.App + "\x00" + cfg.Token + fmt.Sprintf("\x00allow_effects=%t", cfg.AllowEffects))
}
func signCache(r cacheRecord, token string) string {
	r.MAC = ""
	raw, _ := json.Marshal(r)
	m := hmac.New(sha256.New, []byte(token))
	_, _ = m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}
func validMAC(r cacheRecord, token string) bool {
	a, err := hex.DecodeString(r.MAC)
	if err != nil {
		return false
	}
	b, _ := hex.DecodeString(signCache(r, token))
	return hmac.Equal(a, b)
}
func writeCache(path string, r cacheRecord) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".agent-cache-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("persist agent cache: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
