package software

import (
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestLifecycleRequiresDatedIdentityEvidence(t *testing.T) {
	for _, tc := range []struct{ product, version string }{
		{"Java", "11.0.25"}, {"Windows", "10"}, {"Windows", "11"},
		{"Windows", "8.1"}, {"Windows", "7"}, {"Windows", "XP"},
		{"Python", "2.7"}, {"PHP", "7.30"}, {"Apache", "2.20"},
		{"OpenSSL", "1.0.2"}, {"Node", "14.0"}, {"Unknown", "0.9"},
	} {
		t.Run(tc.product+tc.version, func(t *testing.T) {
			s := &types.Software{Product: tc.product, Version: tc.version, SourceName: "Server", IsEndOfLife: true, SupportStatus: SupportEOL}
			EnhanceSoftwareRecord(s)
			if s.IsEndOfLife || s.SupportStatus != SupportUnknown {
				t.Fatalf("unqualified lifecycle conclusion: %+v", s)
			}
		})
	}
}
