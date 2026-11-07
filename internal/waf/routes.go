package waf

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/policy"
)

// RouteConfig is an operator bootstrap capability. PolicyFile is never supplied by a request.
// Higher priorities win; overlapping equal-priority matches are rejected.
type RouteConfig struct {
	ID                 string      `json:"id" yaml:"id"`
	Priority           int         `json:"priority" yaml:"priority"`
	Hosts              []string    `json:"hosts" yaml:"hosts"`
	Methods            []string    `json:"methods" yaml:"methods"`
	PathPrefix         string      `json:"pathPrefix" yaml:"pathPrefix"`
	Upstream           string      `json:"upstream" yaml:"upstream"`
	PolicyFile         string      `json:"policyFile" yaml:"policyFile"`
	PolicyID           string      `json:"policyID" yaml:"policyID"`
	MaxBodyBytes       int64       `json:"maxBodyBytes" yaml:"maxBodyBytes"`
	MaxResponseBytes   int64       `json:"maxResponseBytes" yaml:"maxResponseBytes"`
	MaxConcurrent      int         `json:"maxConcurrent" yaml:"maxConcurrent"`
	CRSProfile         *CRSProfile `json:"crsProfile,omitempty" yaml:"crsProfile,omitempty"`
	UpstreamCA         string      `json:"upstreamCA,omitempty" yaml:"upstreamCA,omitempty"`
	UpstreamServerName string      `json:"upstreamServerName,omitempty" yaml:"upstreamServerName,omitempty"`
	UpstreamCert       string      `json:"upstreamCert,omitempty" yaml:"upstreamCert,omitempty"`
	UpstreamKey        string      `json:"upstreamKey,omitempty" yaml:"upstreamKey,omitempty"`
}

type routeBinding struct {
	config   RouteConfig
	firewall *Firewall
}
type routeTable struct {
	bindings []routeBinding
	active   int
	retired  bool
}
type routeRouter struct{ current atomic.Pointer[routeTable] }

var routeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var methodToken = regexp.MustCompile(`^[A-Z]{1,32}$`)

func routeConfig(c Config, r RouteConfig) Config {
	c.Routes = nil
	c.Upstream, c.PolicyFile, c.AllowedHosts = r.Upstream, r.PolicyFile, append([]string(nil), r.Hosts...)
	c.MaxBodyBytes, c.MaxResponseBytes, c.MaxConcurrent = r.MaxBodyBytes, r.MaxResponseBytes, r.MaxConcurrent
	if r.CRSProfile != nil {
		c.CRSProfile = r.CRSProfile
	}
	c.UpstreamCA, c.UpstreamServerName, c.UpstreamCert, c.UpstreamKey = r.UpstreamCA, r.UpstreamServerName, r.UpstreamCert, r.UpstreamKey
	return c
}

func prefixMatch(prefix, p string) bool {
	return prefix == "/" || p == prefix || strings.HasPrefix(p, prefix+"/")
}
func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}
func validateRoutes(c Config) error {
	if len(c.Routes) > 128 {
		return errors.New("at most 128 routes")
	}
	if c.MaxConcurrent < 1 || c.MaxConcurrent > 4096 {
		return errors.New("listener maxConcurrent must be 1..4096")
	}
	ids := map[string]bool{}
	for i, r := range c.Routes {
		if !routeToken.MatchString(r.ID) || ids[r.ID] || r.PolicyFile == "" || !routeToken.MatchString(r.PolicyID) || len(r.Hosts) == 0 || len(r.Methods) == 0 || len(r.Hosts) > 64 || len(r.Methods) > 32 {
			return errors.New("routes require unique ID, policyFile, bounded exact hosts and methods")
		}
		ids[r.ID] = true
		if r.PathPrefix == "" || !strings.HasPrefix(r.PathPrefix, "/") || path.Clean(r.PathPrefix) != r.PathPrefix || strings.ContainsAny(r.PathPrefix, "%?#\\\r\n") {
			return errors.New("route pathPrefix must be a canonical segment prefix")
		}
		for _, h := range r.Hosts {
			u, err := url.Parse("http://" + h)
			if err != nil || u.Host != h || u.Hostname() == "" || strings.ContainsAny(h, "*@/\\ \t\r\n") {
				return errors.New("route hosts must be exact authorities")
			}
		}
		for _, m := range r.Methods {
			if !methodToken.MatchString(m) {
				return errors.New("invalid route method")
			}
		}
		if err := ValidateConfig(routeConfig(c, r)); err != nil {
			return fmt.Errorf("route %s: %w", r.ID, err)
		}
		if strings.HasPrefix(r.Upstream, "https:") && r.UpstreamServerName == "" {
			return errors.New("HTTPS route requires explicit upstreamServerName")
		}
		for _, other := range c.Routes[:i] {
			if r.Priority == other.Priority && intersects(r.Hosts, other.Hosts) && intersects(r.Methods, other.Methods) && (prefixMatch(r.PathPrefix, other.PathPrefix) || prefixMatch(other.PathPrefix, r.PathPrefix)) {
				return errors.New("ambiguous equal-priority routes")
			}
		}
	}
	return nil
}

func readRoutePolicy(file string) (*policy.Compiled, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("route policy must be regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, policy.MaxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > policy.MaxBundleBytes {
		return nil, errors.New("route policy too large")
	}
	bundle, err := policy.Parse(b)
	if err != nil {
		return nil, err
	}
	return policy.Compile(bundle)
}

func (f *Firewall) compileRoutes() (*routeTable, error) {
	t := &routeTable{}
	for _, r := range f.cfg.Routes {
		p, err := readRoutePolicy(r.PolicyFile)
		if err != nil {
			t.close()
			return nil, fmt.Errorf("route %s: %w", r.ID, err)
		}
		if p.Bundle().ID != r.PolicyID {
			t.close()
			return nil, fmt.Errorf("route %s policy identity mismatch", r.ID)
		}
		child, err := New(routeConfig(f.cfg, r), p)
		if err != nil {
			t.close()
			return nil, fmt.Errorf("route %s: %w", r.ID, err)
		}
		child.parent = f
		// Policy generations share the binding's admission limit.
		if current := f.router.current.Load(); current != nil {
			for _, old := range current.bindings {
				if old.config.ID == r.ID {
					child.slots = old.firewall.slots
					break
				}
			}
		}
		child.buffers = f.buffers
		child.audit = f.audit
		child.stats = f.stats
		t.bindings = append(t.bindings, routeBinding{r, child})
	}
	sort.Slice(t.bindings, func(i, j int) bool { return t.bindings[i].config.Priority > t.bindings[j].config.Priority })
	return t, nil
}
func (t *routeTable) close() {
	for _, b := range t.bindings {
		_ = b.firewall.Close()
	}
}

// ReloadRoutePolicies reloads only operator-bound files and publishes all revisions together.
// Existing requests retain their selected binding until the response completes.
func (f *Firewall) ReloadRoutePolicies() error {
	f.routeMu.Lock()
	defer f.routeMu.Unlock()
	if f.router == nil || f.draining.Load() {
		return errors.New("routes unavailable")
	}
	t, err := f.compileRoutes()
	if err != nil {
		return err
	}
	old := f.router.current.Swap(t)
	old.retired = true
	if old.active == 0 {
		old.close()
	} else {
		f.retired = append(f.retired, old)
	}
	return nil
}
func (f *Firewall) serveRoute(w http.ResponseWriter, r *http.Request) {
	if f.draining.Load() {
		f.reject(w, r, 503)
		return
	}
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	default:
		f.stats.requests.Add(1)
		f.reject(w, r, 503)
		return
	}
	f.routeMu.Lock()
	t := f.router.current.Load()
	t.active++
	f.routeMu.Unlock()
	defer func() {
		f.routeMu.Lock()
		defer f.routeMu.Unlock()
		t.active--
		if t.retired && t.active == 0 {
			t.close()
			for i, old := range f.retired {
				if old == t {
					f.retired = append(f.retired[:i], f.retired[i+1:]...)
					break
				}
			}
		}
	}()
	for _, field := range []string{r.Host, r.Method, r.URL.Path, r.URL.RawQuery} {
		if len(field) > maxInspectionFieldBytes {
			f.stats.requests.Add(1)
			f.reject(w, r, 414)
			return
		}
	}
	// Reject normalization disagreements rather than selecting a weaker route.
	canonical := path.Clean(r.URL.Path)
	if r.URL.RawPath != "" || (canonical != r.URL.Path && canonical+"/" != r.URL.Path) || strings.ContainsAny(r.URL.Path, "%\\\x00") {
		f.stats.requests.Add(1)
		f.reject(w, r, 400)
		return
	}
	hostKnown := false
	for _, b := range t.bindings {
		if !intersects(b.config.Hosts, []string{r.Host}) {
			continue
		}
		hostKnown = true
		if !slices.Contains(b.config.Methods, r.Method) || !prefixMatch(b.config.PathPrefix, r.URL.Path) {
			continue
		}
		b.firewall.ServeHTTP(w, r)
		return
	}
	if hostKnown {
		f.stats.requests.Add(1)
		f.reject(w, r, 404)
	} else {
		f.stats.requests.Add(1)
		f.reject(w, r, 421)
	}
}

// RouteTarget grants activation for one bootstrap ID, with no path or upstream mutation.
func (f *Firewall) RouteTarget(id string) (*RoutePolicyTarget, error) {
	f.routeMu.Lock()
	defer f.routeMu.Unlock()
	if f.router != nil {
		for _, b := range f.router.current.Load().bindings {
			if b.config.ID == id {
				return &RoutePolicyTarget{f: f, id: id, policyID: b.config.PolicyID}, nil
			}
		}
	}
	return nil, errors.New("unknown route")
}

type RoutePolicyTarget struct {
	f            *Firewall
	id, policyID string
}

func (t *RoutePolicyTarget) Policy() *policy.Compiled {
	t.f.routeMu.Lock()
	defer t.f.routeMu.Unlock()
	for _, b := range t.f.router.current.Load().bindings {
		if b.config.ID == t.id {
			return b.firewall.Policy()
		}
	}
	return nil
}
func (t *RoutePolicyTarget) ActivatePolicy(p *policy.Compiled, expectedRevision string) error {
	if p == nil || p.Bundle().ID != t.policyID {
		return errors.New("route policy identity mismatch")
	}
	t.f.routeMu.Lock()
	defer t.f.routeMu.Unlock()
	if t.f.draining.Load() {
		return errors.New("routes unavailable")
	}
	for _, b := range t.f.router.current.Load().bindings {
		if b.config.ID == t.id {
			if expectedRevision == "" || b.firewall.Policy().Revision() != expectedRevision {
				return errors.New("route policy revision conflict")
			}
			b.firewall.SetPolicy(p)
			return nil
		}
	}
	return errors.New("unknown route")
}
