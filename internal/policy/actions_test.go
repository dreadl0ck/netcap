package policy

import (
	"strings"
	"testing"
)

func TestTypedEffectsParseAdmissionAndIdentity(t *testing.T) {
	for _, kind := range []string{"block_source", "quarantine", "drop_flow", "reject_flow", "rate_source", "redirect_source", "notify"} {
		profile, target := "", "client"
		if kind == "quarantine" || kind == "rate_source" || kind == "redirect_source" {
			profile = "operator"
		}
		if strings.HasSuffix(kind, "_flow") {
			target = "source"
		}
		r := effectRule()
		r.Effects = []Effect{{Kind: kind, Profile: profile, Target: target, Scope: "edge", Duration: "10s"}}
		if _, err := Compile(bundle(r)); err == nil {
			t.Fatal("effects admitted by default")
		}
		c, err := CompileWithOptions(bundle(r), CompileOptions{AllowEffects: true})
		if err != nil {
			t.Fatal(err)
		}
		e := effectEvent()
		e.Network = NetworkEvent{SrcIP: e.ClientIP, DstIP: "198.51.100.1", Transport: "tcp", SrcPort: 12345, DstPort: 443}
		d, err := c.Evaluate(e)
		if err != nil || len(d.Effects) != 1 || d.Effects[0].Kind != kind {
			t.Fatalf("%s: %+v %v", kind, d, err)
		}
		i := d.Effects[0]
		if strings.HasSuffix(kind, "_flow") {
			other := i
			other.Flow.SourcePort++
			if IntentID(other) == i.ID {
				t.Fatal("different flows share intent identity")
			}
		}
	}
	for _, kind := range []string{"terminate_flow", "reset_quic", "reject_application", "rate_requests", "shell", "iptables"} {
		r := effectRule()
		r.Effects = []Effect{{Kind: kind, Target: "source", Scope: "edge", Duration: "10s"}}
		if _, err := CompileWithOptions(bundle(r), CompileOptions{AllowEffects: true}); err == nil {
			t.Fatalf("unsupported %s silently compiled", kind)
		}
	}
	for _, raw := range []string{
		`{"version":"1","id":"test","mode":"enforce","default":"allow","rules":[{"id":"q","expression":"true","action":"deny","effects":[{"kind":"quarantine","profile":"operator","target":"source","scope":"edge","duration":"10s"}]}]}`,
		"version: '1'\nid: test\nmode: enforce\ndefault: allow\nrules:\n- id: q\n  expression: 'true'\n  action: deny\n  effects:\n  - kind: quarantine\n    profile: operator\n    target: source\n    scope: edge\n    duration: 10s\n",
	} {
		b, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = CompileWithOptions(b, CompileOptions{AllowEffects: true}); err != nil {
			t.Fatal(err)
		}
	}
}
