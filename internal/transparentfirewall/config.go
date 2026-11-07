// Package transparentfirewall places explicitly configured TCP message gateways
// on a routed service path. Gateways must already run in the target namespace.
package transparentfirewall

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

type Config struct {
	NetworkNamespace string
	IngressInterface string
	// OriginalService accepts one unicast IP or CIDR. A prefix still routes to
	// one gateway with a fixed upstream, not an automatic original-destination proxy.
	OriginalService           string
	OriginalPort, GatewayPort int
	ManagementPeers           []string // CIDRs exempt in both directions
	Protocol                  string   // explicit TCP gateway protocol
	// TLSMode must explicitly be plaintext or terminated. The caller owns TLS
	// certificates and gateway configuration; opaque pass-through is unsupported.
	TLSMode string
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func normalize(c Config) (Config, netip.Prefix, error) {
	if !identifier.MatchString(c.NetworkNamespace) || c.NetworkNamespace == "default" || !identifier.MatchString(c.IngressInterface) || len(c.IngressInterface) > 15 || c.IngressInterface == "lo" {
		return c, netip.Prefix{}, errors.New("explicit non-default named namespace and non-loopback ingress interface required")
	}
	if c.OriginalPort < 1 || c.OriginalPort > 65535 || c.GatewayPort < 1 || c.GatewayPort > 65535 {
		return c, netip.Prefix{}, errors.New("explicit service and gateway TCP ports in 1..65535 required")
	}
	switch c.Protocol {
	case "redis", "dnp3", "modbus", "dns-tcp", "dns-tls", "postgres", "smtp", "mysql":
	default:
		return c, netip.Prefix{}, errors.New("explicit supported TCP gateway protocol required")
	}
	if c.TLSMode != "plaintext" && c.TLSMode != "terminated" {
		return c, netip.Prefix{}, errors.New("TLS mode must explicitly be plaintext or terminated; opaque TLS is not inspected")
	}
	if c.Protocol == "dns-tls" && c.TLSMode != "terminated" {
		return c, netip.Prefix{}, errors.New("dns-tls requires terminated TLS mode")
	}
	p, err := netip.ParsePrefix(c.OriginalService)
	if err != nil {
		if a, e := netip.ParseAddr(c.OriginalService); e == nil {
			p = netip.PrefixFrom(a, a.BitLen())
			err = nil
		}
	}
	if err != nil || !p.IsValid() || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() || p.Bits() == 0 {
		return c, p, errors.New("explicit unicast service IP or non-default CIDR required")
	}
	p = p.Masked()
	c.OriginalService = p.String()
	c.ManagementPeers = append([]string(nil), c.ManagementPeers...)
	for i, s := range c.ManagementPeers {
		peer, err := netip.ParsePrefix(s)
		if err != nil || peer.Addr().Is4In6() {
			return c, p, fmt.Errorf("invalid management peer CIDR %q", s)
		}
		c.ManagementPeers[i] = peer.Masked().String()
	}
	return c, p, nil
}
