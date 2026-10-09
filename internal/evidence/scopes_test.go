package evidence

import "testing"

func TestScopeCollisionsNeverBecomeUniqueAgain(t *testing.T) {
	c := &Capture{manifest: CaptureManifest{Status: "done"}}
	c.ObserveScope("1:flow", 0, []uint16{10})
	c.ObserveScope("1:flow", 0, []uint16{10})
	if c.scopeSnapshot().Entries[0].Ambiguous {
		t.Fatal("repeated packets created ambiguity")
	}
	c.ObserveScope("1:flow", 0, []uint16{20})
	c.ObserveScope("1:flow", 0, []uint16{10})
	c.closed = true
	l := c.scopeSnapshot()
	if !l.Complete || !l.Entries[0].Ambiguous {
		t.Fatalf("collision erased: %+v", l)
	}
	c.ObserveScope("1:other", 0, nil)
	c.ObserveScope("1:other", 1, nil)
	if !c.scopes["1:other"].Ambiguous {
		t.Fatal("interface collision ignored")
	}
}

func TestScopeOverflowRemainsVisible(t *testing.T) {
	c := &Capture{manifest: CaptureManifest{Status: "done"}, scopes: make(map[string]CommunityScope)}
	for i := 0; i < MaxCommunityScopes; i++ {
		c.scopes[string(rune(i+1))] = CommunityScope{}
	}
	c.ObserveScope("1:new", 0, nil)
	if len(c.scopes) != MaxCommunityScopes || c.scopeSnapshot().Overflow != 1 {
		t.Fatal("scope limit not enforced")
	}
}

func TestFilteredOfflineInputsDoNotClaimInterfaceScope(t *testing.T) {
	c := &Capture{manifest: CaptureManifest{Config: CaptureConfig{Kind: "file", BPF: "udp"}}}
	c.ObserveScope("1:flow", 0, nil)
	if len(c.scopeSnapshot().Entries) != 0 {
		t.Fatal("offline BPF scope claimed without preserved interface metadata")
	}
}
