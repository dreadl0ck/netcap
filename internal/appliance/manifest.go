// Package appliance provisions operator-owned named network topologies.
package appliance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/networkfirewall"

	"gopkg.in/yaml.v3"
)

const MaxManifestBytes = 64 << 10

type Manifest struct {
	TargetID   string   `json:"targetID,omitempty" yaml:"targetID,omitempty"`
	Version    string   `json:"version" yaml:"version"`
	Mode       string   `json:"mode" yaml:"mode"`
	Nonce      string   `json:"nonce" yaml:"nonce"`
	Namespaces []string `json:"namespaces" yaml:"namespaces"`
	Links      []Link   `json:"links" yaml:"links"`
	Routes     []Route  `json:"routes" yaml:"routes"`
	Forward    []string `json:"forward" yaml:"forward"`
	Packet     Packet   `json:"packet" yaml:"packet"`
}
type Packet struct {
	Namespace              string   `json:"namespace" yaml:"namespace"`
	Interface              string   `json:"interface" yaml:"interface"`
	ProtectedCIDRs         []string `json:"protectedCIDRs" yaml:"protectedCIDRs"`
	ManagementDestinations []string `json:"managementDestinations" yaml:"managementDestinations"`
	Queue                  uint16   `json:"queue" yaml:"queue"`
}

func (m Manifest) NetworkConfig() networkfirewall.Config {
	return networkfirewall.Config{Namespace: m.Packet.Namespace, Interface: m.Packet.Interface, ProtectedCIDRs: m.Packet.ProtectedCIDRs, ManagementDestinations: m.Packet.ManagementDestinations, Hook: "forward", Queue: m.Packet.Queue, MaxQueueLen: 1024, Deadline: 100 * time.Millisecond, FailureVerdict: networkfirewall.Deny, OwnershipNonce: m.Nonce}
}

type denyEvaluator struct{}

func (denyEvaluator) EvaluatePacket(networkfirewall.PacketEvent) (networkfirewall.Decision, error) {
	return networkfirewall.Decision{Verdict: networkfirewall.Deny}, nil
}

type Endpoint struct {
	Namespace string   `json:"namespace" yaml:"namespace"`
	Interface string   `json:"interface" yaml:"interface"`
	CIDRs     []string `json:"cidrs" yaml:"cidrs"`
}
type Link struct {
	A Endpoint `json:"a" yaml:"a"`
	B Endpoint `json:"b" yaml:"b"`
}
type Route struct {
	Namespace   string `json:"namespace" yaml:"namespace"`
	Destination string `json:"destination" yaml:"destination"`
	Via         string `json:"via" yaml:"via"`
	Interface   string `json:"interface" yaml:"interface"`
}
type Operation struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Arguments []string `json:"arguments"`
}
type Plan struct {
	Version    string      `json:"version"`
	Digest     string      `json:"digest"`
	Nonce      string      `json:"nonce"`
	Operations []Operation `json:"operations"`
	Conntrack  string      `json:"conntrack"`
}

func Parse(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifestBytes {
		return m, errors.New("manifest exceeds 65536 bytes")
	}
	// YAML's strict decoder accepts JSON too and rejects duplicate mapping keys.
	{
		d := yaml.NewDecoder(bytes.NewReader(b))
		d.KnownFields(true)
		if err := d.Decode(&m); err != nil {
			return m, err
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return m, errors.New("one YAML document required")
		}
	}
	return m, m.Validate()
}

var name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)
var nonce = regexp.MustCompile(`^[a-f0-9]{32}$`)

func privatePrefix(p netip.Prefix) bool {
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		block := netip.MustParsePrefix(s)
		if block.Contains(p.Addr()) && p.Bits() >= block.Bits() {
			return true
		}
	}
	return false
}

func (m Manifest) Validate() error {
	if m.Version != "netcap-appliance/v1" || (m.Mode != "lab" && m.Mode != "production") || !nonce.MatchString(m.Nonce) {
		return errors.New("version netcap-appliance/v1, mode lab or production and immutable 128-bit hex nonce required")
	}
	if m.Mode == "production" && !name.MatchString(m.TargetID) {
		return errors.New("production requires explicit topology targetID")
	}
	if len(m.Namespaces) < 1 || len(m.Namespaces) > 8 || len(m.Links) > 16 || len(m.Routes) > 64 {
		return errors.New("topology exceeds bounded lab scope")
	}
	ns := map[string]bool{}
	for _, n := range m.Namespaces {
		if !name.MatchString(n) || n == "default" || ns[n] {
			return errors.New("unique explicit non-default named namespaces required")
		}
		ns[n] = true
	}
	ends := map[string]Endpoint{}
	addresses := map[netip.Addr]bool{}
	for _, l := range m.Links {
		if l.A.Namespace == l.B.Namespace {
			return errors.New("veth peers must be in different named namespaces")
		}
		for _, e := range []Endpoint{l.A, l.B} {
			key := e.Namespace + "/" + e.Interface
			if !ns[e.Namespace] || !name.MatchString(e.Interface) || e.Interface == "lo" || ends[key].Interface != "" || len(e.CIDRs) == 0 || len(e.CIDRs) > 4 {
				return errors.New("invalid or duplicate interface endpoint")
			}
			ends[key] = e
			for _, s := range e.CIDRs {
				p, err := netip.ParsePrefix(s)
				if err != nil || !privatePrefix(p) || s != p.String() || p.Addr().Is4In6() || addresses[p.Addr()] {
					return fmt.Errorf("unique private lab interface CIDR required: %s", s)
				}
				addresses[p.Addr()] = true
			}
		}
	}
	routes := map[string]bool{}
	for _, r := range m.Routes {
		p, err := netip.ParsePrefix(r.Destination)
		via, e := netip.ParseAddr(r.Via)
		key := r.Namespace + "/" + r.Destination
		endpoint := ends[r.Namespace+"/"+r.Interface]
		if err != nil || e != nil || !privatePrefix(p) || r.Destination != p.String() || r.Via != via.String() || p != p.Masked() || via.Is4() != p.Addr().Is4() || endpoint.Interface == "" || routes[key] {
			return errors.New("routes require unique private canonical destination, matching family and declared interface; no default routes")
		}
		onlink := false
		for _, cidr := range endpoint.CIDRs {
			local, _ := netip.ParsePrefix(cidr)
			if local.Contains(via) && via != local.Addr() {
				onlink = true
			}
		}
		if !onlink {
			return errors.New("route gateway must be on the declared interface subnet")
		}
		routes[key] = true
	}
	fwd := map[string]bool{}
	for _, n := range m.Forward {
		if !ns[n] || fwd[n] {
			return errors.New("forwarding requires unique declared namespaces")
		}
		fwd[n] = true
	}
	if ends[m.Packet.Namespace+"/"+m.Packet.Interface].Interface == "" || !fwd[m.Packet.Namespace] {
		return errors.New("packet scope requires a declared forwarding namespace/interface")
	}
	if len(m.Forward) != 1 {
		return errors.New("one fenced packet gateway per lab topology required")
	}
	if len(m.Packet.ProtectedCIDRs) > 16 || len(m.Packet.ManagementDestinations) > 16 {
		return errors.New("packet scope exceeds bounded lab prefixes")
	}
	for _, s := range append(append([]string{}, m.Packet.ProtectedCIDRs...), m.Packet.ManagementDestinations...) {
		p, e := netip.ParsePrefix(s)
		if e != nil || p != p.Masked() || s != p.String() || !privatePrefix(p) {
			return errors.New("packet scope requires canonical private non-default lab prefixes")
		}
	}
	for _, cidr := range ends[m.Packet.Namespace+"/"+m.Packet.Interface].CIDRs {
		p, _ := netip.ParsePrefix(cidr)
		covered := false
		for _, s := range m.Packet.ProtectedCIDRs {
			scope, _ := netip.ParsePrefix(s)
			if scope == p.Masked() {
				covered = true
			}
		}
		if !covered {
			return errors.New("every ingress subnet/family must be protected explicitly")
		}
	}
	if _, err := networkfirewall.New(m.NetworkConfig(), denyEvaluator{}); err != nil {
		return err
	}
	return nil
}

type bootstrapKey struct{}
type Bootstrap struct {
	Scope          firewallauth.Scope
	ReviewedDigest string
	Approvals      *firewallauth.Approvals
	Receipt        string
}

func ApprovalDigest(planDigest, operation string) string {
	return firewallauth.Digest(struct{ Plan, Operation string }{planDigest, operation})
}

func WithBootstrap(ctx context.Context, b Bootstrap) context.Context {
	return context.WithValue(ctx, bootstrapKey{}, b)
}
func AuthorizeProduction(ctx context.Context, m Manifest) error {
	p, err := m.Plan()
	if err != nil {
		return err
	}
	b, ok := ctx.Value(bootstrapKey{}).(Bootstrap)
	if !ok || m.Mode != "production" || b.Scope.Target != m.TargetID || b.Scope.Tenant == "" || b.Scope.App == "" || b.Scope.Environment == "" || b.ReviewedDigest != p.Digest {
		return errors.New("production requires bootstrap target binding and exact reviewed manifest digest")
	}
	return firewallauth.Require(ctx, firewallauth.Deploy, b.Scope)
}

func (m Manifest) Plan() (Plan, error) {
	if err := m.Validate(); err != nil {
		return Plan{}, err
	}
	b, _ := json.Marshal(m)
	p := Plan{Version: m.Version, Digest: fmt.Sprintf("%x", sha256.Sum256(b)), Nonce: m.Nonce, Operations: []Operation{}, Conntrack: "preserve all entries; existing NAT flows retain their original mapping until expiry; no global flush"}
	add := func(kind, ns string, args ...string) {
		p.Operations = append(p.Operations, Operation{ID: fmt.Sprintf("%03d", len(p.Operations)), Kind: kind, Namespace: ns, Arguments: args})
	}
	for _, n := range m.Namespaces {
		add("namespace", n, n)
	}
	add("packet", m.Packet.Namespace)
	for _, l := range m.Links {
		add("veth", l.A.Namespace, l.A.Interface, l.B.Namespace, l.B.Interface)
		for _, e := range []Endpoint{l.A, l.B} {
			for _, cidr := range e.CIDRs {
				add("address", e.Namespace, e.Interface, cidr)
			}
			add("up", e.Namespace, e.Interface)
		}
	}
	for _, r := range m.Routes {
		add("route", r.Namespace, r.Destination, r.Via, r.Interface)
	}
	// Forwarding is last; initial provisioning never enables a half-built path.
	for _, n := range m.Forward {
		add("forward", n)
	}
	return p, nil
}
