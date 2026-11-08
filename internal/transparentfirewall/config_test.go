package transparentfirewall

import "testing"

func testConfig() Config {
	return Config{NetworkNamespace: "tfw-gateway", IngressInterface: "g0", OriginalService: "10.91.0.2", OriginalPort: 6379, GatewayPort: 16379, Protocol: "redis", TLSMode: "plaintext"}
}

func TestExplicitScope(t *testing.T) {
	c := testConfig()
	_, p, err := normalize(c)
	if err != nil || p.String() != "10.91.0.2/32" {
		t.Fatalf("%v %v", p, err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.NetworkNamespace = "default" }, func(c *Config) { c.NetworkNamespace = "../host" }, func(c *Config) { c.IngressInterface = "lo" }, func(c *Config) { c.IngressInterface = "g0\"; flush ruleset" }, func(c *Config) { c.OriginalService = "0.0.0.0/0" }, func(c *Config) { c.OriginalService = "::/0" }, func(c *Config) { c.OriginalService = "::ffff:10.1.1.1" }, func(c *Config) { c.OriginalPort = 0 }, func(c *Config) { c.GatewayPort = 65536 }, func(c *Config) { c.Protocol = "dns" }, func(c *Config) { c.TLSMode = "passthrough" }, func(c *Config) { c.TLSMode = "" }, func(c *Config) { c.ManagementPeers = []string{"bad"} },
	} {
		c := testConfig()
		change(&c)
		if _, _, err := normalize(c); err == nil {
			t.Fatalf("unsafe config accepted: %+v", c)
		}
	}
	c.OriginalService = "fd91::2"
	if _, p, err := normalize(c); err != nil || p.Bits() != 128 {
		t.Fatalf("IPv6: %v %v", p, err)
	}
}
