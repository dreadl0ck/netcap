package networkdetect

import (
	"fmt"
	"net/netip"
)

func addressIn(ip string, ranges []string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, s := range ranges {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
			return true
		}
		if p, err := netip.ParseAddr(s); err == nil && p.Unmap() == a {
			return true
		}
	}
	return false
}

func (e *Engine) networkRole(ip string) string {
	if len(e.config.InternalNetworks) == 0 {
		return "unknown (internalNetworks not configured)"
	}
	if addressIn(ip, e.config.InternalNetworks) {
		return "internal"
	}
	return "external"
}

func (e *Engine) smtpRole(ev Event) (expected bool, qualification string) {
	src, dst := e.networkRole(ev.SrcIP), e.networkRole(ev.DstIP)
	role := "unknown (smtpRelays not configured)"
	if len(e.config.SMTPRelays) > 0 {
		role = "unlisted source"
	}
	if addressIn(ev.SrcIP, e.config.SMTPRelays) {
		role = "configured relay"
		expected = src == "internal" || dst == "internal"
	}
	return expected, fmt.Sprintf("SMTP source role: %s; network direction: %s -> %s; unlisted/unknown roles are not evidence of a spambot", role, src, dst)
}
