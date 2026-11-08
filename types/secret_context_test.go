package types

import (
	"strings"
	"testing"
)

func TestSecretObservedEndpoints(t *testing.T) {
	for _, tc := range []struct{ flow, src, dst string }{
		{"192.0.2.1:50000->192.0.2.2:21", "192.0.2.1", "192.0.2.2"},
		{"[2001:db8::1]:50000->[2001:db8::2]:21", "2001:db8::1", "2001:db8::2"},
		{"2001:db8::1:50000->2001:db8::2:21", "2001:db8::1", "2001:db8::2"},
		{"synthetic-flow", "", ""},
		{"not-an-ip:80->192.0.2.2:21", "", "192.0.2.2"},
	} {
		s := &Secret{Flow: tc.flow}
		if s.Src() != tc.src || s.Dst() != tc.dst {
			t.Fatal(tc, s.Src(), s.Dst())
		}
	}
}

func TestSecretMetricsExcludeAuthenticationMaterial(t *testing.T) {
	s := &Secret{Service: "test-fixture", User: "private-user", Password: "private-password", Notes: "private-notes"}
	metric := secretMetric.WithLabelValues(s.Service)
	if strings.Contains(metric.Desc().String(), "Password") || strings.Contains(metric.Desc().String(), "User") || strings.Contains(metric.Desc().String(), "Notes") {
		t.Fatal(metric.Desc())
	}
	s.Inc()
}

func TestSecretJSONDoesNotMutateOccurrenceTime(t *testing.T) {
	s := &Secret{Timestamp: 1700000000123456789}
	a, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.JSON()
	if err != nil || a != b || s.Timestamp != 1700000000123456789 {
		t.Fatal("JSON changed credential occurrence time", err)
	}
}
