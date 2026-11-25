package networkdetect

import "testing"

func TestFlashReferralRequiresSameClientAndCloseTiming(t *testing.T) {
	leaf := ApplicationObservation{At: 2e9, Scope: Scope{Sensor: "local", Interface: "test"}, Kind: "flash", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Host: "plugin.example.net", CommunityID: "fixture"}
	ref := leaf
	ref.At, ref.Kind, ref.Status, ref.ReferrerHost = 1e9, "http", 200, "other.example.org"
	for _, tc := range []struct {
		name   string
		change func(*ApplicationObservation, *ApplicationObservation)
		want   bool
	}{
		{"cross-site", func(_, _ *ApplicationObservation) {}, true},
		{"same-site", func(r, _ *ApplicationObservation) { r.ReferrerHost = "home.example.net" }, false},
		{"other-client", func(_, f *ApplicationObservation) { f.SrcIP = "10.0.0.2" }, false},
		{"expired", func(_, f *ApplicationObservation) { f.At = 100e9 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewApplication(DefaultConfig())
			r, f := ref, leaf
			tc.change(&r, &f)
			var found bool
			for _, alert := range append(append(e.Observe(r), e.Observe(f)...), e.Flush()...) {
				found = found || alert.RuleName == "http.flash-referral"
			}
			if found != tc.want {
				t.Fatalf("flash referral matched=%t, want %t", found, tc.want)
			}
		})
	}
}
