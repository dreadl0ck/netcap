package config

import "testing"

func TestModbusRTUEndpoints(t *testing.T) {
	for _, s := range []string{"host:502", "192.0.2.1", "192.0.2.1:0", "192.0.2.1:65536", "::1:502", "[fe80::1%en0]:502", "192.0.2.1:502,"} {
		if (&Config{ModbusRTUEndpoints: s}).ValidateModbusRTUEndpoints() == nil {
			t.Errorf("accepted %q", s)
		}
	}
	c := &Config{ModbusRTUEndpoints: "192.0.2.1:1502, [2001:db8::1]:502"}
	if err := c.ValidateModbusRTUEndpoints(); err != nil {
		t.Fatal(err)
	}
	if !c.IsModbusRTUEndpoint("192.0.2.1", 1502) || !c.IsModbusRTUEndpoint("2001:db8:0:0::1", 502) || c.IsModbusRTUEndpoint("192.0.2.2", 1502) || c.IsModbusRTUEndpoint("192.0.2.1", 502) {
		t.Fatal("endpoint matching")
	}
	if (&Config{}).IsModbusRTUEndpoint("192.0.2.1", 1502) {
		t.Fatal("enabled by default")
	}
}
