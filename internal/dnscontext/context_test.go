package dnscontext

import (
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func exchange(t *Tracker, scope, name, ip string, at int64, ttl uint32) {
	question := []*types.DNSQuestion{{Name: name, Type: 1, Class: 1}}
	t.Observe(&types.DNS{Timestamp: at - 1, ID: 7, SrcIP: "192.0.2.10", DstIP: "192.0.2.53", SrcPort: 41000, DstPort: 53, Questions: question}, scope)
	t.Observe(&types.DNS{Timestamp: at, ID: 7, QR: true, SrcIP: "192.0.2.53", DstIP: "192.0.2.10", SrcPort: 53, DstPort: 41000, Questions: question, Answers: []*types.DNSResourceRecord{{Name: name, Type: 1, Class: 1, IP: ip, TTL: ttl}}}, scope)
}

func TestSnapshotsSurviveLaterAnswersAndEviction(t *testing.T) {
	tracker := New()
	tracker.limit = 1
	exchange(tracker, "0/10", "First.Example.", "198.51.100.1", 100, 60)
	first := tracker.Lookup("0/10", "192.0.2.10", "198.51.100.1", 101)
	if first.State != "resolved" || first.Name != "first.example" || first.AnsweredAt != 100 {
		t.Fatalf("bad snapshot: %+v", first)
	}
	exchange(tracker, "0/10", "second.example", "198.51.100.1", 200, 60)
	if first.Name != "first.example" {
		t.Fatal("later answer rewrote earlier snapshot")
	}
	exchange(tracker, "0/10", "third.example", "198.51.100.2", 300, 60)
	if len(tracker.answers) != 1 || first.Name != "first.example" {
		t.Fatal("eviction violated bounds or rewrote snapshot")
	}
}

func TestScopeTTLAndResponseValidity(t *testing.T) {
	tracker := New()
	exchange(tracker, "0/10", "example.test", "198.51.100.1", 100, 1)
	for _, tc := range []struct {
		scope string
		at    int64
	}{{"0/20", 101}, {"1/10", 101}, {"0/10", 99}, {"0/10", 100 + 1e9 + 1}} {
		if got := tracker.Lookup(tc.scope, "192.0.2.10", "198.51.100.1", tc.at); got.State != "unobserved" {
			t.Fatalf("invalid context accepted: %+v", got)
		}
	}
	tracker.Observe(&types.DNS{Timestamp: 200, QR: true, DstIP: "192.0.2.10", Questions: []*types.DNSQuestion{{Name: "unsolicited.test", Type: 1, Class: 1}}, Answers: []*types.DNSResourceRecord{{Type: 1, Class: 1, IP: "198.51.100.2", TTL: 60}}}, "0/10")
	if got := tracker.Lookup("0/10", "192.0.2.10", "198.51.100.2", 201); got.State != "unobserved" {
		t.Fatal("unsolicited answer accepted")
	}
}
