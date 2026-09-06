package config

import (
	"fmt"
	"net/netip"
	"strings"
)

func (c *Config) ValidateModbusRTUEndpoints() error {
	if c.ModbusRTUEndpoints == "" {
		return nil
	}
	for _, value := range strings.Split(c.ModbusRTUEndpoints, ",") {
		ep, err := netip.ParseAddrPort(strings.TrimSpace(value))
		if err != nil || ep.Port() == 0 || ep.Addr().Zone() != "" {
			return fmt.Errorf("invalid Modbus RTU destination %q: require IP:port or [IPv6]:port with port 1..65535", value)
		}
	}
	return nil
}

func (c *Config) IsModbusRTUEndpoint(ip string, port uint16) bool {
	// Every TCP conversation asks; parse nothing when the feature is off.
	if c.ModbusRTUEndpoints == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, value := range strings.Split(c.ModbusRTUEndpoints, ",") {
		ep, err := netip.ParseAddrPort(strings.TrimSpace(value))
		if err == nil && ep.Port() != 0 && ep.Port() == port && ep.Addr().Zone() == "" && ep.Addr().Unmap() == addr.Unmap() {
			return true
		}
	}
	return false
}
