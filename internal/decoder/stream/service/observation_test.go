package service

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestPreferObservationOrderIndependent(t *testing.T) {
	type observation struct {
		banner         string
		ts             int64
		server, client int
	}
	observations := []observation{
		{"z", 1, 100, 100},
		{"zz", -1, 100, 100},
		{"aa", 1, 100, 100},
		{"aa", 0, 2, 3},
		{"aa", 0, 3, 2},
		{"aa", 0, 3, 4},
	}
	var visit func([]observation, []observation)
	visit = func(prefix, remaining []observation) {
		if len(remaining) == 0 {
			s := NewService(prefix[0].ts, prefix[0].server, prefix[0].client, "")
			s.Banner = prefix[0].banner
			for _, o := range prefix[1:] {
				s.PreferObservation([]byte(o.banner), o.ts, o.server, o.client)
			}
			if s.Banner != "aa" || s.Timestamp != 0 || s.BytesServer != 3 || s.BytesClient != 4 {
				t.Fatalf("order %v: got %+v", prefix, s.Service)
			}
			return
		}
		for i, o := range remaining {
			next := append([]observation(nil), remaining[:i]...)
			next = append(next, remaining[i+1:]...)
			visit(append(prefix, o), next)
		}
	}
	visit(nil, observations)
}

func TestResetProbeMatchRestoresPortName(t *testing.T) {
	s := &service{Service: &types.Service{Name: "http", PortName: "fixture", Product: "old", MatchedProbeID: "old"}}
	s.ResetProbeMatch()
	if s.Name != "fixture" || s.Product != "" || s.MatchedProbeID != "" {
		t.Fatalf("stale probe metadata: %+v", s.Service)
	}
}
