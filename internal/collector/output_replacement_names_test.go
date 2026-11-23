package collector

import "testing"

// A -y re-run must own aliased audit files, or a stale v0.16.11 GTPv1U.ncap.gz
// or a VRRP.ncap.gz from the previous run survives beside the new output.
func TestManagedCaptureOutputIncludesAuditAliases(t *testing.T) {
	for _, name := range []string{"VRRP.ncap.gz", "GTPv1U.ncap.gz", "GTPv1U.ncap", "ApplePktap.ncap.gz", "GTP.csv", "TCP.json.gz", "Alert.ncap.gz"} {
		if !managedCaptureOutput(name) {
			t.Errorf("%s not managed", name)
		}
	}
	for _, name := range []string{"Nope.ncap.gz", "notes.json", "TCP.json"} {
		if managedCaptureOutput(name) {
			t.Errorf("%s managed", name)
		}
	}
}
