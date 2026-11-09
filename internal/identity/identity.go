package identity

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

const Filename = "Hosts.json"

type Evidence struct {
	At     int64  `json:"at"`
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Source string `json:"source"`
	Flow   string `json:"flow,omitempty"`
}
type Account struct {
	At               int64      `json:"at"`
	Flow             string     `json:"flow,omitempty"`
	FullNameState    string     `json:"fullNameState"`
	FullNameEvidence []Evidence `json:"fullNameEvidence,omitempty"`
	Name             string     `json:"name"`
	Domain           string     `json:"domain,omitempty"`
	FullName         string     `json:"fullName,omitempty"`
	Source           string     `json:"source"`
}
type Binding struct {
	MAC    string `json:"mac"`
	Count  uint64 `json:"observations"`
	Source string `json:"source"`
}
type Host struct {
	MAC           string     `json:"mac,omitempty"`
	MACState      string     `json:"macState"`
	Scope         string     `json:"scope"`
	IP            string     `json:"ip"`
	Hostname      string     `json:"hostname,omitempty"`
	HostnameState string     `json:"hostnameState"`
	Evidence      []Evidence `json:"evidence"`
	Accounts      []Account  `json:"accounts"`
	Bindings      []Binding  `json:"bindings"`
}
type Report struct {
	Directory       []DirectoryObservation `json:"directory,omitempty"`
	UnscopedRecords uint64                 `json:"unscopedRecords"`
	Schema          int                    `json:"schema"`
	Hosts           []Host                 `json:"hosts"`
	Overflow        uint64                 `json:"overflow"`
	Limitations     []string               `json:"limitations"`
}
type DirectoryObservation struct {
	SID      string   `json:"sid,omitempty"`
	Scope    string   `json:"scope"`
	Account  string   `json:"account,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	FullName string   `json:"fullName,omitempty"`
	Client   string   `json:"observedClient,omitempty"`
	Evidence Evidence `json:"evidence"`
}
type directory struct {
	SID                                     string
	Scope, Name, Domain, FullName, Hostname string
	Client                                  string
	Source, Flow                            string
	At                                      int64
}
type state struct {
	host     Host
	bindings map[string]Binding
	evidence map[string]int
	accounts map[string]Account
}
type Engine struct {
	hosts     map[string]*state
	directory map[string]directory
	overflow  uint64
}

func New() *Engine { return &Engine{hosts: map[string]*state{}, directory: map[string]directory{}} }
func (e *Engine) host(scope, ip string) *state {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsUnspecified() || a.IsMulticast() {
		return nil
	}
	ip = a.Unmap().String()
	key := scope + "|" + ip
	if h := e.hosts[key]; h != nil {
		return h
	}
	if len(e.hosts) >= 65536 {
		e.overflow++
		return nil
	}
	h := &state{host: Host{Scope: scope, IP: ip}, bindings: map[string]Binding{}, evidence: map[string]int{}, accounts: map[string]Account{}}
	e.hosts[key] = h
	return h
}
func (e *Engine) Bind(scope, ip, mac, source string) {
	h := e.host(scope, ip)
	if h == nil || mac == "" {
		return
	}
	b := h.bindings[mac]
	if b.MAC == "" && len(h.bindings) >= 4 {
		e.overflow++
		return
	}
	b.MAC = mac
	b.Count++
	if source != "observed-link-source" || b.Source == "" {
		b.Source = source
	}
	h.bindings[mac] = b
}
func (e *Engine) add(scope, ip, kind, value, source, flow string, at int64) {
	value = strings.TrimSpace(strings.TrimRight(value, "\x00"))
	if value == "" || len(value) > 512 {
		return
	}
	h := e.host(scope, ip)
	if h == nil {
		return
	}
	key := kind + "|" + value + "|" + source
	if index, ok := h.evidence[key]; ok {
		old := &h.host.Evidence[index]
		if at < old.At || at == old.At && flow < old.Flow {
			old.At, old.Flow = at, flow
		}
		return
	}
	if len(h.evidence) >= 128 {
		e.overflow++
		return
	}
	h.evidence[key] = len(h.host.Evidence)
	h.host.Evidence = append(h.host.Evidence, Evidence{at, kind, value, source, flow})
}
func (e *Engine) account(scope, ip, name, domain, source, flow string, at int64) {
	if strings.HasSuffix(name, "$") {
		e.add(scope, ip, "hostname", strings.TrimSuffix(name, "$"), source+" machine account", flow, at)
		return
	}
	if name == "" || len(name) > 256 || len(domain) > 256 {
		return
	}
	h := e.host(scope, ip)
	if h == nil {
		return
	}
	if len(h.accounts) >= 32 {
		e.overflow++
		return
	}
	key := strings.ToLower(domain + "|" + name)
	if old, ok := h.accounts[key]; ok && (old.Source < source || old.Source == source && (old.At < at || old.At == at && old.Flow <= flow)) {
		return
	}
	h.accounts[key] = Account{Name: name, Domain: domain, Source: source, At: at, Flow: flow}
}
func (e *Engine) Observe(scope string, m proto.Message) {
	switch r := m.(type) {
	case *types.NBNS:
		if r.ResponseCode != 0 || !r.Response && r.OpCode != 5 && r.OpCode != 8 {
			return
		}
		for _, n := range r.Names {
			if n.Section == "question" || n.Group || n.Type != 0x20 || n.IP == "" || n.Suffix != 0 && n.Suffix != 3 && n.Suffix != 0x20 {
				continue
			}
			if !r.Response && n.IP != r.SrcIP {
				continue
			}
			e.add(scope, n.IP, "hostname", n.Name, "NBNS address assertion", "community:"+r.CommunityID, r.Timestamp)
		}
	case *types.Secret:
		if r.Service == secret.IdentityService {
			if ip, _, _, _, ok := secret.SecretEndpoints(r.Flow); ok {
				e.account(scope, ip, r.User, r.Domain, "NTLMSSP observed identity (unverified authentication)", r.Flow, r.Timestamp)
				e.add(scope, ip, "hostname", r.Workstation, "NTLMSSP workstation claim", r.Flow, r.Timestamp)
			}
		}
	case *types.Kerberos:
		ip := r.SrcIP
		if r.MessageTypeCode == 11 || r.MessageTypeCode == 13 {
			ip = r.DstIP
		}
		e.account(scope, ip, r.ClientName, r.Realm, "Kerberos", r.Flow, r.Timestamp)
	case *types.SMB:
		ip := r.SrcIP
		if r.IsResponse {
			ip = r.DstIP
		}
		e.account(scope, ip, r.Username, r.Domain, "SMB NTLM", "community:"+r.CommunityID, r.Timestamp)
	case *types.DHCPv4:
		if r.MessageTypeCode == 5 {
			e.Bind(scope, r.YourClientIP, r.ClientHWAddr, "DHCP ACK")
			e.add(scope, r.YourClientIP, "hostname", r.Hostname, "DHCP", "", r.Timestamp)
		}
	case *types.LDAP:
		if r.Operation != "SearchResultEntry" {
			return
		}
		values := map[string]string{}
		for _, a := range r.Attributes {
			if len(a.Values) == 1 && len(a.Values[0]) <= 512 {
				values[strings.ToLower(a.Name)] = string(a.Values[0])
			}
		}
		name := values["samaccountname"]
		if name == "" {
			name = r.SearchAccount
		}
		var dc []string
		for _, part := range strings.Split(r.DN, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.EqualFold(key, "DC") {
				dc = append(dc, value)
			}
		}
		full := values["displayname"]
		if full == "" {
			full = strings.TrimSpace(values["givenname"] + " " + values["sn"])
		}
		d := directory{Scope: scope, Name: name, Domain: strings.Join(dc, "."), FullName: full, Hostname: values["dnshostname"], Source: "LDAP " + r.DN, Flow: r.Flow, At: r.Timestamp}
		if name != "" || full != "" {
			e.rememberDirectory(d)
		}
		if ip := values["iphostnumber"]; ip != "" && d.Hostname != "" {
			e.add(scope, ip, "hostname", d.Hostname, "LDAP ipHostNumber/dNSHostName", r.Flow, r.Timestamp)
		}
	case *types.DCERPC:
		// Query results identify accounts, not the IP of the RPC server.
		for _, i := range r.Identities {
			if i.AccountName != "" && (i.FullName != "" || i.SID != "") && len(e.directory) < 65536 {
				client := r.SrcIP
				if r.PacketType == 2 {
					client = r.DstIP
				}
				if r.InterfaceName == "LSARPC" {
					client = ""
				}
				e.rememberDirectory(directory{SID: i.SID, Scope: scope, Name: i.AccountName, Domain: i.Domain, FullName: i.FullName, Client: client, Source: r.InterfaceName + " " + r.OperationName, Flow: r.Flow, At: r.Timestamp})
			}
		}
	}
}
func (e *Engine) rememberDirectory(d directory) {
	key := d.Scope + "|" + strings.ToLower(d.Domain+"|"+d.Name) + "|" + d.FullName + "|" + d.Source + "|" + d.Client + "|" + d.SID
	if old, ok := e.directory[key]; ok {
		if old.At < d.At || old.At == d.At && old.Flow <= d.Flow {
			return
		}
	} else if len(e.directory) >= 65536 {
		e.overflow++
		return
	}
	e.directory[key] = d
}
func (e *Engine) Seed(scope string, p *types.DeviceProfile) {
	for _, ip := range p.DeviceIPs {
		e.Bind(scope, ip, p.MacAddr, "ARP/DHCP/NDP binding")
		for _, name := range p.Hostnames {
			e.add(scope, ip, "hostname", name, "profile aggregate (time not attributed)", "", 0)
		}
	}
}

func (e *Engine) Discover(scope, ip string, names []string) {
	for _, name := range names {
		e.add(scope, ip, "hostname", name, "discovery address assertion", "", 0)
	}
}

// SeedBoundProfile covers captures with link-source observations but no ARP/DHCP.
// A MAC carrying several IPs is a possible gateway, so it cannot transfer names.
func (e *Engine) SeedBoundProfile(p *types.DeviceProfile) {
	var candidate *state
	for _, h := range e.hosts {
		if _, ok := h.bindings[p.MacAddr]; !ok {
			continue
		}
		if candidate != nil {
			return
		}
		candidate = h
	}
	if candidate != nil {
		for _, name := range p.Hostnames {
			e.add(candidate.host.Scope, candidate.host.IP, "hostname", name, "profile with unique link-source binding", "", 0)
		}
	}
}
func (e *Engine) Report() Report {
	r := Report{Schema: 1, Overflow: e.overflow, Limitations: []string{"Bindings retain competing MAC observations; link-source counts alone do not establish IP ownership", "Directory names are joined to observed accounts, never to an LDAP/RPC server merely carrying the response", "Unknown or conflicting identities are retained; absence is not proof of no account"}}
	directoryIndex := map[string][]directory{}
	accountDomains := map[string]map[string]bool{}
	for _, s := range e.hosts {
		for _, a := range s.accounts {
			key := s.host.Scope + "|" + strings.ToLower(a.Name)
			if accountDomains[key] == nil {
				accountDomains[key] = map[string]bool{}
			}
			accountDomains[key][strings.ToLower(a.Domain)] = true
		}
	}
	for _, d := range e.directory {
		r.Directory = append(r.Directory, DirectoryObservation{SID: d.SID, Scope: d.Scope, Account: d.Name, Domain: d.Domain, FullName: d.FullName, Client: d.Client, Evidence: Evidence{At: d.At, Kind: "directory-subject", Value: d.FullName, Source: d.Source, Flow: d.Flow}})
		key := d.Scope + "|" + strings.ToLower(d.Name)
		directoryIndex[key] = append(directoryIndex[key], d)
	}
	for _, s := range e.hosts {
		h := s.host
		names := map[string]string{}
		for _, v := range h.Evidence {
			if v.Kind == "hostname" {
				key := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(v.Value), "."), ".local")
				if old, ok := names[key]; !ok || v.Value < old {
					names[key] = v.Value
				}
			}
		}
		for _, a := range s.accounts {
			var candidates []directory
			for _, d := range directoryIndex[h.Scope+"|"+strings.ToLower(a.Name)] {
				if d.Client != "" && d.Client != h.IP {
					continue
				}
				if d.Domain == "" && d.Client == "" && len(accountDomains[h.Scope+"|"+strings.ToLower(a.Name)]) > 1 {
					continue
				}
				if d.Scope != h.Scope || !strings.EqualFold(d.Name, a.Name) {
					continue
				}
				if a.Domain != "" && d.Domain != "" && !strings.EqualFold(a.Domain, d.Domain) {
					continue
				}
				candidates = append(candidates, d)
			}
			full := map[string]bool{}
			domains := map[string]bool{}
			for _, d := range candidates {
				if d.FullName != "" {
					a.FullNameEvidence = append(a.FullNameEvidence, Evidence{At: d.At, Kind: "full-name", Value: d.FullName, Source: d.Source, Flow: d.Flow})
				}
				if d.Domain != "" {
					domains[strings.ToLower(d.Domain)] = true
				}
				if d.FullName != "" {
					full[d.FullName] = true
				}
			}
			a.FullNameState = "unknown"
			if len(full) == 1 && len(domains) <= 1 {
				for name := range full {
					a.FullName = name
				}
				a.Source += " + directory account match"
				a.FullNameState = "directory-account-match"
				if len(domains) == 0 {
					a.FullNameState = "account-name-match-domain-unconfirmed"
				}
			} else if len(full) > 1 || len(domains) > 1 {
				a.FullNameState = "conflicting-directory-observations"
			}
			sort.Slice(a.FullNameEvidence, func(i, j int) bool {
				x, y := a.FullNameEvidence[i], a.FullNameEvidence[j]
				return x.Value+"|"+x.Source+"|"+x.Flow < y.Value+"|"+y.Source+"|"+y.Flow
			})
			h.Accounts = append(h.Accounts, a)
		}
		for _, b := range s.bindings {
			h.Bindings = append(h.Bindings, b)
		}
		var authoritative []Binding
		var top, second Binding
		for _, b := range h.Bindings {
			if b.Source != "observed-link-source" {
				authoritative = append(authoritative, b)
			}
			if b.Count > top.Count {
				second = top
				top = b
			} else if b.Count > second.Count {
				second = b
			}
		}
		h.MACState = "unknown"
		if len(authoritative) == 1 {
			h.MAC, h.MACState = authoritative[0].MAC, "binding-observed"
		} else if len(authoritative) > 1 {
			h.MACState = "conflicting-bindings"
		} else if top.Count >= 3 && top.Count >= second.Count*4 {
			h.MAC, h.MACState = top.MAC, "dominant-link-source"
		}
		h.HostnameState = "unknown"
		if len(names) == 1 {
			for _, name := range names {
				h.Hostname = name
			}
			h.HostnameState = "observed"
		} else if len(names) > 1 {
			h.HostnameState = "conflicting-observations"
		}
		sort.Slice(h.Evidence, func(i, j int) bool {
			a, b := h.Evidence[i], h.Evidence[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.Value != b.Value {
				return a.Value < b.Value
			}
			return a.Source < b.Source
		})
		sort.Slice(h.Accounts, func(i, j int) bool {
			return h.Accounts[i].Domain+"|"+h.Accounts[i].Name < h.Accounts[j].Domain+"|"+h.Accounts[j].Name
		})
		sort.Slice(h.Bindings, func(i, j int) bool { return h.Bindings[i].MAC < h.Bindings[j].MAC })
		r.Hosts = append(r.Hosts, h)
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return r.Hosts[i].Scope+"|"+r.Hosts[i].IP < r.Hosts[j].Scope+"|"+r.Hosts[j].IP })
	sort.Slice(r.Directory, func(i, j int) bool {
		x, y := r.Directory[i], r.Directory[j]
		return x.Scope+"|"+x.Domain+"|"+x.Account+"|"+x.FullName+"|"+x.Evidence.Source+"|"+x.Client+"|"+x.SID < y.Scope+"|"+y.Domain+"|"+y.Account+"|"+y.FullName+"|"+y.Evidence.Source+"|"+y.Client+"|"+y.SID
	})
	return r
}
