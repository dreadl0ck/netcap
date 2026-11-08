package enforcer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type ActionKind string

const (
	BlockSource    ActionKind = "block_source"
	Quarantine     ActionKind = "quarantine"
	DropFlow       ActionKind = "drop_flow"
	RejectFlow     ActionKind = "reject_flow"
	RateSource     ActionKind = "rate_source"
	RedirectSource ActionKind = "redirect_source"
)

type Service struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// Profile is bootstrap authority. Requests can name it, never supply its contents.
type Profile struct {
	Kind        ActionKind `json:"kind"`
	Services    []Service  `json:"services"`
	Rate        uint32     `json:"rate,omitempty"`
	Burst       uint32     `json:"burst,omitempty"`
	Unit        string     `json:"unit,omitempty"` // packets or bytes, per second
	Destination string     `json:"destination,omitempty"`
	Port        uint16     `json:"port,omitempty"`
}

// Flow is an ingress five-tuple; Source is the lease's independently attributed IP.
type Flow struct {
	Destination     string `json:"destination" yaml:"destination"`
	Protocol        string `json:"protocol" yaml:"protocol"`
	SourcePort      uint16 `json:"source_port" yaml:"source_port"`
	DestinationPort uint16 `json:"destination_port" yaml:"destination_port"`
}

type Action struct {
	Kind    ActionKind `json:"kind,omitempty"`
	Profile string     `json:"profile,omitempty"`
	Flow    Flow       `json:"flow,omitempty"`
}

func (a *Action) UnmarshalJSON(raw []byte) error {
	type wire Action
	var value wire
	if err := decodeObject(raw, &value, "kind", "profile", "flow"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if flow, ok := fields["flow"]; ok {
		if err := decodeObject(flow, &value.Flow, "destination", "protocol", "source_port", "destination_port"); err != nil {
			return err
		}
	}
	*a = Action(value)
	return nil
}

func (a Action) EffectiveKind() ActionKind {
	if a.Kind == "" {
		return BlockSource
	}
	return a.Kind
}

func validService(s Service) bool { return (s.Protocol == "tcp" || s.Protocol == "udp") && s.Port != 0 }

func normalizeProfiles(c *Config) error {
	if len(c.Profiles) > 32 || len(c.ProtectedServices) > 32 {
		return errors.New("too many profiles or protected services")
	}
	c.ProtectedServices = append([]Service(nil), c.ProtectedServices...)
	for _, s := range c.ProtectedServices {
		if !validService(s) {
			return errors.New("invalid protected service")
		}
	}
	profiles := make(map[string]Profile, len(c.Profiles))
	for name, p := range c.Profiles {
		if !identifier.MatchString(name) || len(p.Services) == 0 || len(p.Services) > 32 {
			return errors.New("invalid action profile name or service count")
		}
		if p.Kind != Quarantine && p.Kind != RateSource && p.Kind != RedirectSource {
			return errors.New("unsupported profile action")
		}
		if (c.Scope.Hook == "prerouting") != (p.Kind == RedirectSource) {
			return errors.New("redirect requires a dedicated prerouting scope; filter effects require input/forward")
		}
		p.Services = append([]Service(nil), p.Services...)
		seen := map[Service]bool{}
		for _, s := range p.Services {
			if !validService(s) || seen[s] {
				return errors.New("invalid or duplicate profile service")
			}
			seen[s] = true
			for _, protected := range c.ProtectedServices {
				if s == protected {
					return errors.New("profile includes protected management service")
				}
			}
		}
		sort.Slice(p.Services, func(i, j int) bool {
			if p.Services[i].Protocol == p.Services[j].Protocol {
				return p.Services[i].Port < p.Services[j].Port
			}
			return p.Services[i].Protocol < p.Services[j].Protocol
		})
		if p.Kind == RateSource {
			if (p.Unit != "packets" && p.Unit != "bytes") || p.Rate == 0 || p.Rate > 1000000000 || p.Burst == 0 || p.Burst > 1000000000 {
				return errors.New("rate profile requires bounded packet/byte token bucket")
			}
		} else if p.Unit != "" || p.Rate != 0 || p.Burst != 0 {
			return errors.New("rate parameters on non-rate action")
		}
		if p.Kind == RedirectSource {
			for _, service := range p.Services {
				if service.Protocol != c.Scope.Protocol {
					return errors.New("redirect profile services must use the bootstrap transport protocol")
				}
			}
			a, err := netip.ParseAddr(p.Destination)
			dst, _ := netip.ParsePrefix(c.Scope.DestinationCIDR)
			if err != nil || a.String() != p.Destination || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.Is4() != dst.Addr().Is4() || p.Port == 0 {
				return errors.New("redirect requires canonical operator destination and port of same family")
			}
			for _, raw := range c.ProtectedCIDRs {
				protected, _ := netip.ParsePrefix(raw)
				if protected.Contains(a) {
					return errors.New("redirect destination is protected")
				}
			}
		} else if p.Destination != "" || p.Port != 0 {
			return errors.New("redirect parameters on non-redirect action")
		}
		profiles[name] = p
	}
	c.Profiles = profiles
	if c.Scope.Hook == "prerouting" && len(profiles) == 0 {
		return errors.New("prerouting requires redirect profiles")
	}
	return nil
}

func (c *Controller) validateAction(l Lease) error {
	a := l.Action
	k := a.EffectiveKind()
	if k == BlockSource || k == DropFlow || k == RejectFlow {
		if c.config.Scope.Hook == "prerouting" || a.Profile != "" {
			return errors.New("action unavailable in this scope")
		}
		for _, protected := range c.config.ProtectedServices {
			if protected == (Service{c.config.Scope.Protocol, c.config.Scope.Port}) {
				return errors.New("protected management service")
			}
		}
	} else {
		p, ok := c.config.Profiles[a.Profile]
		if !ok || p.Kind != k {
			return errors.New("unknown or unauthorized action profile")
		}
	}
	if k == DropFlow || k == RejectFlow {
		f := a.Flow
		dst, err := netip.ParseAddr(f.Destination)
		prefix, _ := netip.ParsePrefix(c.config.Scope.DestinationCIDR)
		if err != nil || dst.String() != f.Destination || dst.Is4In6() || dst.Zone() != "" || !prefix.Contains(dst) || f.Protocol != c.config.Scope.Protocol || f.DestinationPort != c.config.Scope.Port || f.SourcePort == 0 {
			return errors.New("flow must be canonical and within bootstrap service scope")
		}
	} else if a.Flow != (Flow{}) {
		return errors.New("flow selector on non-flow action")
	}
	if k != BlockSource && k != DropFlow && k != RejectFlow && k != Quarantine && k != RateSource && k != RedirectSource {
		return fmt.Errorf("unsupported action %q", k)
	}
	return nil
}

// selectorKey reserves one exact action selector, allowing independent flows.
func selectorKey(l Lease) string {
	return fmt.Sprintf("%s|%s|%s|%v", l.Source, l.Action.EffectiveKind(), l.Action.Profile, l.Action.Flow)
}

// Overlapping packet actions are rejected rather than depending on nft insertion
// order. Different five-tuples or disjoint service profiles can coexist.
func (c *Controller) selectorsConflict(a, b Lease) bool {
	if a.Source != b.Source {
		return false
	}
	af, bf := a.Action.Flow, b.Action.Flow
	if af != (Flow{}) && bf != (Flow{}) {
		return af == bf
	}
	services := func(l Lease) []Service {
		if l.Action.Flow != (Flow{}) {
			return []Service{{l.Action.Flow.Protocol, l.Action.Flow.DestinationPort}}
		}
		if l.Action.Profile != "" {
			return c.config.Profiles[l.Action.Profile].Services
		}
		return []Service{{c.config.Scope.Protocol, c.config.Scope.Port}}
	}
	for _, x := range services(a) {
		for _, y := range services(b) {
			if x == y {
				return true
			}
		}
	}
	return false
}

func (c *Controller) actionKinds() []string {
	result := []string{}
	protected := false
	for _, service := range c.config.ProtectedServices {
		protected = protected || service == (Service{c.config.Scope.Protocol, c.config.Scope.Port})
	}
	if c.config.Scope.Hook != "prerouting" && !protected {
		result = append(result, string(BlockSource), string(DropFlow), string(RejectFlow))
	}
	for _, p := range c.config.Profiles {
		found := false
		for _, k := range result {
			if k == string(p.Kind) {
				found = true
			}
		}
		if !found {
			result = append(result, string(p.Kind))
		}
	}
	sort.Strings(result)
	return result
}

func (c *Controller) capabilities() enforcerCapabilities {
	_, simulated := c.backend.(*DryRunBackend)
	return enforcerCapabilities{Scope: c.config.Scope, DryRun: c.config.DryRun || simulated, MaxLeases: c.config.MaxLeases, MaxTTLSeconds: int64(c.config.MaxTTL / time.Second), ProtectedCIDRs: append([]string{}, c.config.ProtectedCIDRs...), Actions: c.actionKinds(), AbsoluteDeadlines: true, Profiles: c.config.Profiles, ProtectedServices: c.config.ProtectedServices, PacketFlow: true, RejectSemantics: "matching ingress packet: TCP reset or UDP ICMP port-unreachable; no proactive reset", RedirectSemantics: "DNAT new connections only; existing conntrack bindings may outlive expiry"}
}
