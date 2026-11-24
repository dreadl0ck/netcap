//go:build !appstore

package webui

import "testing"

func TestAuxiliaryCaptureIsOnUnlessDisabled(t *testing.T) {
	for value, want := range map[string]bool{"": true, "1": true, "true": true, "0": false} {
		t.Setenv("NETCAP_AUXILIARY_CAPTURE", value)
		if got := auxiliaryCaptureEnabled(); got != want {
			t.Errorf("NETCAP_AUXILIARY_CAPTURE=%q: %v, want %v", value, got, want)
		}
	}
}
