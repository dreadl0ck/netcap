package waf

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestStrictConfig(t *testing.T) {
	c := config("https://origin.example")
	j, _ := json.Marshal(c)
	y, _ := yaml.Marshal(c)
	for _, data := range [][]byte{j, y} {
		got, err := LoadConfig(data)
		if err != nil || got.Upstream != c.Upstream {
			t.Fatalf("roundtrip: %v", err)
		}
	}
	for _, data := range []string{
		strings.TrimSuffix(string(j), "}") + `,"unknown":true}`,
		strings.TrimSuffix(string(j), "}") + `,"maxBodyBytes":1}`,
		strings.TrimSuffix(string(j), "}") + `,"Listen":"127.0.0.1:9"}`,
		string(j) + " {}",
		string(y) + "unknown: true\n",
		string(y) + "listen: 127.0.0.1:9\n",
		string(y) + "---\n{}",
		"null", "[]", " ", strings.Repeat("x", 65537),
	} {
		if _, err := LoadConfig([]byte(data)); err == nil {
			t.Fatalf("accepted ambiguous config %q", data[:min(len(data), 200)])
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Version = "v1" }, func(c *Config) { c.MaxBodyBytes = 0 }, func(c *Config) { c.MaxConcurrent = 0 }, func(c *Config) { c.BodyTimeout = "0s" }, func(c *Config) { c.Upstream = "http://user:pass@host" }, func(c *Config) { c.Upstream = "http://host/path" }, func(c *Config) { c.Upstream = "http://host:99999" }, func(c *Config) { c.TrustedProxyCIDRs = []string{"10.0.0.0"} }, func(c *Config) { c.TLSCert = "cert" }, func(c *Config) { c.Listen = ":bad" }, func(c *Config) { c.AllowedHosts = []string{"bad/host"} },
	} {
		c := config("http://origin.example")
		mutate(&c)
		if err := ValidateConfig(c); err == nil {
			t.Fatalf("accepted invalid config: %+v", c)
		}
	}
}

func TestConfigBodySpoolLimits(t *testing.T) {
	for _, field := range []string{"maxBodyBytes", "maxResponseBytes"} {
		for _, limit := range []int64{MaxInspectionBodyBytes + 1, 0, -1} {
			c := config("http://origin.example")
			if field == "maxBodyBytes" {
				c.MaxBodyBytes = limit
			} else {
				c.MaxResponseBytes = limit
			}
			err := ValidateConfig(c)
			if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "67108864") || !strings.Contains(err.Error(), "native") {
				t.Fatalf("%s=%d: expected explanatory limit rejection, got %v", field, limit, err)
			}
			for _, marshal := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal} {
				data, err := marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := LoadConfig(data); err == nil {
					t.Fatalf("loaded unsupported %s=%d", field, limit)
				}
			}
		}
	}
	c := config("http://origin.example")
	c.MaxBodyBytes = MaxInspectionBodyBytes
	c.MaxResponseBytes = MaxInspectionBodyBytes
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("64 MiB spool boundary config rejected: %v", err)
	}
}

func TestConfigAggregateBufferBudget(t *testing.T) {
	for _, limit := range []int64{0, 64 << 10, 64 << 20, 1 << 30} {
		c := config("http://origin.example")
		c.MaxBufferedBytes = limit
		for _, marshal := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal} {
			data, err := marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(data)
			if err != nil || loaded.MaxBufferedBytes != limit {
				t.Fatalf("budget config %d: loaded=%d error=%v", limit, loaded.MaxBufferedBytes, err)
			}
		}
	}
	for _, limit := range []int64{-1, (1 << 30) + 1} {
		c := config("http://origin.example")
		c.MaxBufferedBytes = limit
		if err := ValidateConfig(c); err == nil || !strings.Contains(err.Error(), "maxBufferedBytes") {
			t.Fatalf("accepted invalid aggregate quota %d: %v", limit, err)
		}
	}
}
