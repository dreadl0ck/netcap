package appliance

import (
	"encoding/json"
	"os"
	"testing"
)

func fixture(t *testing.T) Manifest {
	t.Helper()
	b, e := os.ReadFile("../../examples/firewall/appliance-lab.json")
	if e != nil {
		t.Fatal(e)
	}
	m, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestManifestBoundary(t *testing.T) {
	m := fixture(t)
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Mode = "production" }, func(m *Manifest) { m.Namespaces[0] = "default" },
		func(m *Manifest) { m.Routes[0].Destination = "0.0.0.0/0" }, func(m *Manifest) { m.Routes[0].Via = "192.168.1.1" },
		func(m *Manifest) { m.Links[0].A.CIDRs[0] = "8.8.8.8/24" }, func(m *Manifest) { m.Packet.Interface = "eth0" },
		func(m *Manifest) { m.Links[0].A.CIDRs[0] = "10.180.0.2/7" },
		func(m *Manifest) { m.Links[0].A.CIDRs[1] = "fd80:0000::2/64" },
	} {
		b, _ := json.Marshal(m)
		copy, e := Parse(b)
		if e != nil {
			t.Fatal(e)
		}
		mutate(&copy)
		if e = copy.Validate(); e == nil {
			t.Fatal("unsafe topology accepted")
		}
	}
	for _, b := range [][]byte{[]byte(`{"command":"sh"}`), []byte("version: netcap-appliance/v1\ncommand: sh"), []byte("---\nmode: lab\n---\nmode: lab"), make([]byte, MaxManifestBytes+1)} {
		if _, e := Parse(b); e == nil {
			t.Fatal("invalid/unknown input accepted")
		}
	}
}
func TestPlanStableAndGuardBeforeRouting(t *testing.T) {
	m := fixture(t)
	a, e := m.Plan()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := m.Plan()
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatal("unstable JSON plan")
	}
	guard := false
	for _, op := range a.Operations {
		if op.Kind == "packet" {
			guard = true
		}
		if (op.Kind == "route" || op.Kind == "forward") && !guard {
			t.Fatal("routing precedes fail-closed guard")
		}
	}
	if !guard {
		t.Fatal("missing packet guard")
	}
}
