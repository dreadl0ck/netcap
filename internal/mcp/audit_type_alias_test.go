package mcp

import "testing"

func TestCanonicalAuditTypeNameAcceptsFileAliases(t *testing.T) {
	for name, want := range map[string]string{"GTPv1U": "GTP", "gtpv1u": "GTP", "VRRP": "VRRPv2", "vrrpv2": "VRRPv2", "tcp": "TCP"} {
		if got, err := canonicalAuditTypeName(name); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", name, got, err, want)
		}
	}
	if _, err := canonicalAuditTypeName("NotAType"); err == nil {
		t.Fatal("unknown type accepted")
	}
}
