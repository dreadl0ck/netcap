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

// MaxInspectionBodyBytes bounds each wire and expanded disk-spooled representation.
const MaxInspectionBodyBytes int64 = 64 << 20

const maxInspectionHeaderBytes = 32 << 10
const maxInspectionFieldBytes = 65536

type Config struct {
	Routes             []RouteConfig `json:"routes,omitempty" yaml:"routes,omitempty"`
	CRSProfile         *CRSProfile   `json:"crsProfile,omitempty" yaml:"crsProfile,omitempty"`
	ClientCA           string        `json:"clientCA,omitempty" yaml:"clientCA,omitempty"`
	UpstreamCert       string        `json:"upstreamCert,omitempty" yaml:"upstreamCert,omitempty"`
	UpstreamKey        string        `json:"upstreamKey,omitempty" yaml:"upstreamKey,omitempty"`
	Version            string        `json:"version" yaml:"version"`
	Listen             string        `json:"listen" yaml:"listen"`
	AdminListen        string        `json:"adminListen" yaml:"adminListen"`
	Upstream           string        `json:"upstream" yaml:"upstream"`
	PolicyFile         string        `json:"policyFile" yaml:"policyFile"`
	MaxBodyBytes       int64         `json:"maxBodyBytes" yaml:"maxBodyBytes"`
	MaxResponseBytes   int64         `json:"maxResponseBytes" yaml:"maxResponseBytes"`
	MaxBufferedBytes   int64         `json:"maxBufferedBytes,omitempty" yaml:"maxBufferedBytes,omitempty"`
	MaxConcurrent      int           `json:"maxConcurrent" yaml:"maxConcurrent"`
	BodyTimeout        string        `json:"bodyTimeout" yaml:"bodyTimeout"`
	TLSCert            string        `json:"tlsCert,omitempty" yaml:"tlsCert,omitempty"`
	TLSKey             string        `json:"tlsKey,omitempty" yaml:"tlsKey,omitempty"`
	UpstreamCA         string        `json:"upstreamCA,omitempty" yaml:"upstreamCA,omitempty"`
	UpstreamServerName string        `json:"upstreamServerName,omitempty" yaml:"upstreamServerName,omitempty"`
	TrustedProxyCIDRs  []string      `json:"trustedProxyCIDRs,omitempty" yaml:"trustedProxyCIDRs,omitempty"`
	InspectResponse    bool          `json:"inspectResponse" yaml:"inspectResponse"`
	AllowedHosts       []string      `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	CorazaCRS          bool          `json:"corazaCRS,omitempty" yaml:"corazaCRS,omitempty"`
	// API artifacts are trusted bootstrap inputs, independent of policy reloads.
	DescriptorPath      string               `json:"descriptorPath,omitempty" yaml:"descriptorPath,omitempty"`
	DescriptorSHA256    string               `json:"descriptorSHA256,omitempty" yaml:"descriptorSHA256,omitempty"`
	BootstrapDir        string               `json:"bootstrapDir,omitempty" yaml:"bootstrapDir,omitempty"`
	APIValidateResponse bool                 `json:"apiValidateResponse,omitempty" yaml:"apiValidateResponse,omitempty"`
	CRSTargetExclusions []CRSTargetExclusion `json:"crsTargetExclusions,omitempty" yaml:"crsTargetExclusions,omitempty"`
}

// CRSTargetExclusion narrows one application-attack rule to an exact route,
// method and argument. Structural validation and all other targets remain active.
type CRSTargetExclusion struct {
	Path     string `json:"path" yaml:"path"`
	Method   string `json:"method" yaml:"method"`
	Argument string `json:"argument" yaml:"argument"`
	RuleID   int    `json:"ruleID" yaml:"ruleID"`
}

func validateCRSExclusions(c Config) error {
	if len(c.CRSTargetExclusions) > 32 || len(c.CRSTargetExclusions) > 0 && !c.CorazaCRS {
		return errors.New("WAF CRS target exclusions require CRS and at most 32 entries")
	}
	seen := map[CRSTargetExclusion]bool{}
	for _, e := range c.CRSTargetExclusions {
		if e.RuleID < 930000 || e.RuleID > 944999 || e.Path == "" || e.Path[0] != '/' || len(e.Path) > 256 || len(e.Argument) == 0 || len(e.Argument) > 64 || seen[e] {
			return errors.New("invalid or duplicate WAF CRS target exclusion")
		}
		if e.Method != "POST" && e.Method != "PUT" && e.Method != "PATCH" && e.Method != "GET" {
			return errors.New("invalid WAF CRS exclusion method")
		}
		for _, part := range []string{e.Path, e.Argument} {
			for _, r := range part {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '/') {
					return errors.New("invalid WAF CRS exclusion characters")
				}
			}
		}
		if strings.ContainsAny(e.Argument, "/.") {
			return errors.New("WAF CRS exclusion requires a simple argument name")
		}
		seen[e] = true
	}
	return nil
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
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return err
	}
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

func rejectDuplicateKeys(d *json.Decoder) error {
	v, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := v.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("duplicate JSON config key")
			}
			seen[s] = true
		}
		if err := rejectDuplicateKeys(d); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func ValidateConfig(c Config) error {
	if len(c.Routes) > 0 {
		return validateRoutes(c)
	}
	if err := validateProfile(c); err != nil {
		return err
	}
	if (c.UpstreamCert == "") != (c.UpstreamKey == "") {
		return errors.New("upstreamCert and upstreamKey must be paired")
	}
	if c.ClientCA != "" && c.TLSCert == "" {
		return errors.New("clientCA requires listener TLS")
	}
	if c.DescriptorPath != "" || c.DescriptorSHA256 != "" || c.BootstrapDir != "" || c.APIValidateResponse {
		if c.DescriptorPath == "" || len(c.DescriptorSHA256) != 64 || c.BootstrapDir == "" {
			return errors.New("API policy requires descriptorPath, descriptorSHA256 and bootstrapDir")
		}
	}
	if err := validateCRSExclusions(c); err != nil {
		return err
	}
	if c.MaxBufferedBytes < 0 || c.MaxBufferedBytes > 1<<30 {
		return errors.New("maxBufferedBytes must be 0 (64 MiB default) or 1..1073741824 bytes")
	}
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
			return fmt.Errorf("%s must be 1..%d bytes; body-dependent native policies additionally require bodies <=%d bytes", limit.name, MaxInspectionBodyBytes, NativeBodyBytes)
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
	if u.Scheme != "https" && (c.UpstreamCA != "" || c.UpstreamServerName != "" || c.UpstreamCert != "") {
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
