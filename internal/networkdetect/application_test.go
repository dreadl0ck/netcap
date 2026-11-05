package networkdetect

import (
	"fmt"
	"strings"
	"testing"
)

func httpObservation(n int) ApplicationObservation {
	return ApplicationObservation{At: 1700000000000000000 + int64(n)*1e9, Kind: "http", Scope: Scope{Sensor: "fixture", Interface: "pcap"}, SrcIP: "10.0.0.2", DstIP: "8.8.8.8", SrcPort: 40000, DstPort: 80, Method: "GET", Path: fmt.Sprintf("/path-%d", n), Status: 404}
}
func TestHTTPScanNeedsDiversityAndFailureEvidence(t *testing.T) {
	for _, status := range []int{200, 404} {
		e := NewApplication(DefaultConfig())
		count := 0
		for i := 0; i < 80; i++ {
			o := httpObservation(i)
			o.Status = status
			for _, a := range e.Observe(o) {
				if a.Name == "http.scan" {
					count++
				}
			}
		}
		if status == 404 && count != 1 || status == 200 && count != 0 {
			t.Fatal(status, count)
		}
	}
	e := NewApplication(DefaultConfig())
	for i := 0; i < 80; i++ {
		o := httpObservation(i)
		o.Qualification = "unpaired_after_capture_loss"
		for _, a := range e.Observe(o) {
			if a.Name == "http.scan" {
				t.Fatal("unpaired responses invented 4xx evidence")
			}
		}
	}
}
func TestHTTPBeaconInsideOneConnectionIsQualified(t *testing.T) {
	e := NewApplication(DefaultConfig())
	found := false
	for i := 0; i < 12; i++ {
		o := httpObservation(i * 30)
		o.Path = "/fakeurl.htm"
		o.Method = "POST"
		o.Status = 200
		for _, a := range e.Observe(o) {
			if a.Name == "c2.beacon" {
				found = true
				if a.Severity != "low" || !strings.Contains(a.MatchedRecord, "legitimate") {
					t.Fatal("periodicity represented as compromise", a)
				}
			}
		}
	}
	if !found {
		t.Fatal("long-lived HTTP beacon missed")
	}
}
func TestPublicNTLMExcludesSpecialUseAddresses(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "100.64.1.2", "192.0.2.1", "2001:db8::1", "127.0.0.1"} {
		if globalAddress(ip) {
			t.Fatal("special-use address classified public", ip)
		}
	}
	e := NewApplication(DefaultConfig())
	o := httpObservation(0)
	o.Kind = "ntlm"
	o.DstPort = 445
	if a := e.Observe(o); len(a) != 1 || a[0].Name != "policy.public-smb-ntlm" {
		t.Fatal(a)
	}
}
