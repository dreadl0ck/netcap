package behavior

import "net/netip"

type scopedContact struct{ scope, ip string }
type contactPair struct{ scope, src, dst string }

var sharedIPv4 = netip.MustParsePrefix("100.64.0.0/10")

// Pulse on the first observed pair. The indexes contain only retained facts.
type contactIndex struct {
	knownSrc map[scopedContact]bool
	knownDst map[scopedContact]bool
	seen     map[contactPair]bool
}

func newContactIndex(s Snapshot) contactIndex {
	if !s.Policy.FirstPublicContact {
		return contactIndex{}
	}
	c := contactIndex{knownSrc: map[scopedContact]bool{}, knownDst: map[scopedContact]bool{}, seen: map[contactPair]bool{}}
	for _, f := range s.Approved {
		if f.Kind == "service" && f.Protocol == "tcp" {
			scope := scopeKey(f.Scope)
			c.knownSrc[scopedContact{scope, f.SrcIP}] = true
			c.knownDst[scopedContact{scope, f.DstIP}] = true
		}
	}
	for _, observed := range s.Observed {
		c.observe(observed.Fact)
	}
	return c
}

func (c contactIndex) observe(f Fact) bool {
	if c.seen == nil || f.Kind != "service" || f.Protocol != "tcp" {
		return false
	}
	switch f.Port {
	case 0, 53, 80, 443, 853, 8080, 8443:
		return false
	}
	dst, err := netip.ParseAddr(f.DstIP)
	if err != nil || !dst.IsGlobalUnicast() || dst.IsPrivate() || sharedIPv4.Contains(dst) {
		return false
	}
	k := contactPair{scopeKey(f.Scope), f.SrcIP, f.DstIP}
	first := !c.seen[k]
	c.seen[k] = true
	return first
}

func (c contactIndex) novel(f Fact) bool {
	scope := scopeKey(f.Scope)
	return c.knownSrc[scopedContact{scope, f.SrcIP}] && !c.knownDst[scopedContact{scope, f.DstIP}]
}
