// Package waf implements a bounded HTTP reverse-proxy inspection boundary.
package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// MaxInspectionBodyBytes leaves metadata headroom within policy.MaxEventBytes.
// It bounds wire and expanded bodies; larger uploads are unsupported.
const MaxInspectionBodyBytes int64 = 1 << 20

const maxInspectionHeaderBytes = 32 << 10
const maxInspectionFieldBytes = 65536

type Config struct {
	Version            string   `json:"version" yaml:"version"`
	Listen             string   `json:"listen" yaml:"listen"`
	AdminListen        string   `json:"adminListen" yaml:"adminListen"`
	Upstream           string   `json:"upstream" yaml:"upstream"`
	PolicyFile         string   `json:"policyFile" yaml:"policyFile"`
	MaxBodyBytes       int64    `json:"maxBodyBytes" yaml:"maxBodyBytes"`
	MaxResponseBytes   int64    `json:"maxResponseBytes" yaml:"maxResponseBytes"`
	MaxConcurrent      int      `json:"maxConcurrent" yaml:"maxConcurrent"`
	BodyTimeout        string   `json:"bodyTimeout" yaml:"bodyTimeout"`
	TLSCert            string   `json:"tlsCert,omitempty" yaml:"tlsCert,omitempty"`
	TLSKey             string   `json:"tlsKey,omitempty" yaml:"tlsKey,omitempty"`
	UpstreamCA         string   `json:"upstreamCA,omitempty" yaml:"upstreamCA,omitempty"`
	UpstreamServerName string   `json:"upstreamServerName,omitempty" yaml:"upstreamServerName,omitempty"`
	TrustedProxyCIDRs  []string `json:"trustedProxyCIDRs,omitempty" yaml:"trustedProxyCIDRs,omitempty"`
	InspectResponse    bool     `json:"inspectResponse" yaml:"inspectResponse"`
	AllowedHosts       []string `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	CorazaCRS          bool     `json:"corazaCRS,omitempty" yaml:"corazaCRS,omitempty"`
}

func LoadConfig(data []byte) (Config, error) {
	var c Config
	if len(data) > 64<<10 {
		return c, errors.New("WAF config exceeds 65536 bytes")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || len(data) > 64<<10 {
		return c, errors.New("WAF config must contain 1..65536 bytes")
	}
	if data[0] == '{' {
		if err := validateJSONKeys(data); err != nil {
			return c, err
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(&c); err != nil {
			return c, err
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return c, errors.New("expected one config document")
		}
	} else {
		d := yaml.NewDecoder(bytes.NewReader(data))
		d.SetStrict(true)
		if err := d.Decode(&c); err != nil {
			return c, err
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return c, errors.New("expected one config document")
		}
	}
	return c, ValidateConfig(c)
}

func validateJSONKeys(data []byte) error {
	allowed := make(map[string]bool)
	t := reflect.TypeFor[Config]()
	for i := 0; i < t.NumField(); i++ {
		allowed[strings.Split(t.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if _, err := d.Token(); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for d.More() {
		v, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := v.(string)
		if !ok || !allowed[key] || seen[key] {
			return errors.New("unknown or duplicate JSON config key")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
	}
	_, err := d.Token()
	return err
}

func ValidateConfig(c Config) error {
	if c.Version != "netcap-firewall/v1" {
		return errors.New("unsupported WAF config version")
	}
	for _, addr := range []string{c.Listen, c.AdminListen} {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("invalid listen address: %w", err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return errors.New("listen port must be 0..65535")
		}
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("upstream must be an http(s) origin without credentials, query or path")
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		if err != nil || n < 1 || n > 65535 {
			return errors.New("invalid upstream port")
		}
	}
	for _, limit := range []struct {
		name  string
		value int64
	}{{"maxBodyBytes", c.MaxBodyBytes}, {"maxResponseBytes", c.MaxResponseBytes}} {
		if limit.value <= 0 || limit.value > MaxInspectionBodyBytes {
			return fmt.Errorf("%s must be 1..%d bytes (1 MiB); larger inspection bodies are unsupported to reserve metadata space in the native policy event budget", limit.name, MaxInspectionBodyBytes)
		}
	}
	if c.MaxConcurrent <= 0 || c.MaxConcurrent > 4096 {
		return errors.New("explicit concurrency (1..4096) required")
	}
	t, err := time.ParseDuration(c.BodyTimeout)
	if err != nil || t <= 0 || t > 5*time.Minute {
		return errors.New("bodyTimeout must be positive and at most 5m")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tlsCert and tlsKey must be paired")
	}
	if u.Scheme != "https" && (c.UpstreamCA != "" || c.UpstreamServerName != "") {
		return errors.New("upstream TLS options require https")
	}
	for _, s := range c.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR: %w", err)
		}
	}
	for _, h := range c.AllowedHosts {
		if h == "" || strings.ContainsAny(h, "/\\@ \t\r\n") {
			return errors.New("allowedHosts requires exact host authorities")
		}
	}
	return nil
}
