// Package bindings implements immutable operator-enrolled MCP authorities.
package bindings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
)

var component = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Fault struct {
	Status int
	Code   string
}

func (e *Fault) Error() string            { return "operator binding: " + e.Code }
func fault(status int, code string) error { return &Fault{status, code} }

type FileConfig struct {
	Version  int             `json:"version"`
	Sensors  []SensorConfig  `json:"sensors,omitempty"`
	Webhooks []WebhookConfig `json:"webhooks,omitempty"`
}
type SensorConfig struct {
	Name             string `json:"name"`
	SensorID         string `json:"sensorId"`
	KeyFile          string `json:"keyFile"`
	Namespace        string `json:"namespace"`
	MaxBytes         int64  `json:"maxBytes"`
	RetentionSeconds int    `json:"retentionSeconds"`
	MaxRuns          int    `json:"maxRuns"`
}
type WebhookConfig struct {
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint"`
	TokenFile  string `json:"tokenFile"`
	OutboxRoot string `json:"outboxRoot"`
	MaxNotices int    `json:"maxNotices"`
	MaxScopes  int    `json:"maxScopes"`
}
type sensorBinding struct {
	config SensorConfig
	key    []byte
	gate   chan struct{}
	root   os.FileInfo
}
type webhookBinding struct {
	config WebhookConfig
	token  string
	gate   chan struct{}
	root   os.FileInfo
}
type Manager struct {
	sensors     map[string]*sensorBinding
	webhooks    map[string]*webhookBinding
	secretPaths []string
	secretFiles []os.FileInfo
	network     bool
	now         func() time.Time
}

func privateFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fault(400, "invalid_private_configuration")
	}
	f, info, err := artifactio.Open(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return nil, fault(400, "invalid_private_configuration")
	}
	defer f.Close()
	if info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, fault(400, "invalid_private_configuration")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fault(400, "invalid_private_configuration")
	}
	return b, nil
}

// Load resolves private credential files once; results never expose configuration.
func Load(path string, network bool) (*Manager, error) {
	m := &Manager{sensors: map[string]*sensorBinding{}, webhooks: map[string]*webhookBinding{}, network: network, now: time.Now}
	if path == "" {
		return m, nil
	}
	raw, err := privateFile(path, 256<<10)
	if err != nil {
		return nil, err
	}
	var cfg FileConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || cfg.Version != 1 || len(cfg.Sensors) > 16 || len(cfg.Webhooks) > 16 {
		return nil, fault(400, "invalid_operator_configuration")
	}
	m.secretPaths = append(m.secretPaths, path)
	roots := []string{}
	addRoot := func(root string) error {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return fault(400, "invalid_namespace")
		}
		for _, previous := range roots {
			if within(previous, root) || within(root, previous) {
				return fault(400, "overlapping_namespaces")
			}
		}
		roots = append(roots, root)
		return nil
	}
	for _, c := range cfg.Sensors {
		if !component.MatchString(c.Name) || !component.MatchString(c.SensorID) || m.sensors[c.Name] != nil || c.MaxBytes < 1 || c.MaxBytes > 64<<20 || c.RetentionSeconds < 1 || c.RetentionSeconds > 30*24*3600 || c.MaxRuns < 1 || c.MaxRuns > 64 {
			return nil, fault(400, "invalid_sensor_enrollment")
		}
		if err := addRoot(c.Namespace); err != nil {
			return nil, err
		}
		key, err := privateFile(c.KeyFile, 4096)
		if err != nil || len(key) < 32 {
			return nil, fault(400, "invalid_sensor_key")
		}
		m.secretPaths = append(m.secretPaths, c.KeyFile)
		m.sensors[c.Name] = &sensorBinding{config: c, key: append([]byte{}, key...), gate: make(chan struct{}, 1)}
	}
	for _, c := range cfg.Webhooks {
		u, err := url.Parse(c.Endpoint)
		if !component.MatchString(c.Name) || m.webhooks[c.Name] != nil || err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || len(c.Endpoint) > 4096 || c.MaxNotices < 1 || c.MaxNotices > 1000 || c.MaxScopes < 1 || c.MaxScopes > 64 {
			return nil, fault(400, "invalid_webhook_enrollment")
		}
		if err := addRoot(c.OutboxRoot); err != nil {
			return nil, err
		}
		token, err := privateFile(c.TokenFile, 8192)
		if err != nil {
			return nil, fault(400, "invalid_webhook_credential")
		}
		value := strings.TrimSpace(string(token))
		if value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fault(400, "invalid_webhook_credential")
		}
		m.secretPaths = append(m.secretPaths, c.TokenFile)
		m.webhooks[c.Name] = &webhookBinding{config: c, token: value, gate: make(chan struct{}, 1)}
	}
	for _, root := range roots {
		for _, secret := range m.secretPaths {
			if within(root, secret) {
				return nil, fault(400, "credential_inside_namespace")
			}
		}
	}
	for _, root := range roots {
		if err := privateDirectory(root); err != nil {
			return nil, err
		}
	}
	for _, path := range m.secretPaths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fault(400, "invalid_private_configuration")
		}
		m.secretFiles = append(m.secretFiles, info)
	}
	for _, b := range m.sensors {
		b.root, _ = os.Stat(b.config.Namespace)
	}
	for _, b := range m.webhooks {
		b.root, _ = os.Stat(b.config.OutboxRoot)
	}
	return m, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || filepath.IsLocal(rel))
}
func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return fault(503, "namespace_unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return fault(503, "namespace_not_private")
	}
	return nil
}
func pinnedDirectory(path string, identity os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil || identity == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity, info) {
		return fault(409, "operator_namespace_changed")
	}
	return nil
}
func boundedEntries(path string, limit int) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > limit {
		return nil, fault(409, "namespace_entry_budget")
	}
	return entries, nil
}
func acquire(ctx context.Context, gate chan struct{}) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (m *Manager) rejectSecretSource(source string) error {
	for _, secret := range m.secretPaths {
		if within(source, secret) {
			return fault(403, "credential_in_source")
		}
	}
	return nil
}
func (m *Manager) sensor(name string) (*sensorBinding, error) {
	if len(m.sensors) == 0 {
		return nil, fault(503, "sensor_bindings_unconfigured")
	}
	binding := m.sensors[name]
	if binding == nil {
		return nil, fault(404, "unknown_sensor_binding")
	}
	if err := pinnedDirectory(binding.config.Namespace, binding.root); err != nil {
		return nil, err
	}
	return binding, nil
}
func (m *Manager) webhook(name string) (*webhookBinding, error) {
	if len(m.webhooks) == 0 {
		return nil, fault(503, "webhook_bindings_unconfigured")
	}
	binding := m.webhooks[name]
	if binding == nil {
		return nil, fault(404, "unknown_webhook_binding")
	}
	if err := pinnedDirectory(binding.config.OutboxRoot, binding.root); err != nil {
		return nil, err
	}
	return binding, nil
}

func (m *Manager) Public() map[string]any {
	sensors, webhooks := []map[string]any{}, []map[string]any{}
	for _, b := range m.sensors {
		sensors = append(sensors, map[string]any{"name": b.config.Name, "sensor_id": b.config.SensorID, "max_bytes": b.config.MaxBytes, "retention_seconds": b.config.RetentionSeconds, "max_runs": b.config.MaxRuns, "namespace": "operator-owned"})
	}
	for _, b := range m.webhooks {
		webhooks = append(webhooks, map[string]any{"name": b.config.Name, "max_notices": b.config.MaxNotices, "max_scopes": b.config.MaxScopes, "network_enabled": m.network})
	}
	sort.Slice(sensors, func(i, j int) bool { return fmt.Sprint(sensors[i]["name"]) < fmt.Sprint(sensors[j]["name"]) })
	sort.Slice(webhooks, func(i, j int) bool { return fmt.Sprint(webhooks[i]["name"]) < fmt.Sprint(webhooks[j]["name"]) })
	return map[string]any{"version": 1, "configured": len(sensors)+len(webhooks) > 0, "sensors": sensors, "webhooks": webhooks, "credentials": "startup-resolved; never accepted or returned by tools"}
}
