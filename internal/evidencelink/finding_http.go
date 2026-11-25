package evidencelink

import (
	"crypto/sha256"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

type findingURL [sha256.Size]byte

type findingURLKey struct {
	scope  string
	client netip.Addr
	url    findingURL
}

type findingHTTP struct {
	ref                 ContextRef
	method, host, scope string
	client, server      netip.Addr
	uri, referer        findingURL
	status              int32
}

func contextAuthority(raw, scheme string) (authority, name string) {
	if len(raw) > 300 || strings.ContainsAny(raw, " /\\@?#\t\r\n") {
		return "", ""
	}
	var port string
	if host, p, err := net.SplitHostPort(raw); err == nil {
		value, err := strconv.ParseUint(p, 10, 16)
		if err != nil || value == 0 {
			return "", ""
		}
		raw = host
		if !(scheme == "http" && value == 80 || scheme == "https" && value == 443) {
			port = strconv.FormatUint(value, 10)
		}
	}
	if addr := contextAddress(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")); addr.IsValid() {
		name = addr.String()
	} else {
		name = contextName(raw)
	}
	if name == "" {
		return "", ""
	}
	if port != "" {
		return net.JoinHostPort(name, port), name
	}
	if strings.Contains(name, ":") {
		return "[" + name + "]", name
	}
	return name, name
}

// Compare exact normalized URLs, retaining only their digests in the index.
func contextURL(target, host string) (findingURL, string) {
	if len(target) == 0 || len(target) > 4096 || strings.ContainsAny(target, "#\\\r\n") {
		return findingURL{}, ""
	}
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") && host != "" {
		target = "http://" + host + target
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return findingURL{}, ""
	}
	authority, name := contextAuthority(u.Host, u.Scheme)
	if authority == "" {
		return findingURL{}, ""
	}
	if host != "" {
		if expected, _ := contextAuthority(host, u.Scheme); expected != authority {
			return findingURL{}, ""
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.ForceQuery || u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return sha256.Sum256([]byte(u.Scheme + "://" + authority + path)), name
}

func httpContextEligible(h *types.HTTP) bool {
	return h.Timestamp > 0 && h.Host != "" && h.StatusCode >= 200 && h.StatusCode < 300 &&
		(h.Method == "GET" || h.Method == "POST") && len(h.ParseQualifications) == 0 && h.ReassemblyStatus == ""
}

func (i *FindingContext) addFindingHTTP(h *types.HTTP, ref ContextRef) {
	if !httpContextEligible(h) {
		return
	}
	key, client, server := contextFlow(h.CommunityID, h.SrcIP, h.DstIP, h.SrcPort, h.DstPort)
	conn := i.connectionAt(key, h.Timestamp, "TCP")
	uri, host := contextURL(h.URL, h.Host)
	if conn == nil || host == "" {
		return
	}
	referrer, _ := contextURL(h.Referer, "")
	entry := findingHTTP{ref, h.Method, host, conn.scope, client, server, uri, referrer, h.StatusCode}
	addContext(i.http, key, entry)
	addContext(i.urls, findingURLKey{conn.scope, client, uri}, entry)
	i.bytes += 1024 + 2*len(conn.scope) + 2*len(host)
}

func (i *FindingContext) forHTTP(h *types.HTTP) []RelatedEvidence {
	if !httpContextEligible(h) {
		return nil
	}
	key, client, server := contextFlow(h.CommunityID, h.SrcIP, h.DstIP, h.SrcPort, h.DstPort)
	uri, name := contextURL(h.URL, h.Host)
	links := i.addDNSLink(nil, key, h.Timestamp, client, server, name)
	return i.appendReferrers(links, key, h.Timestamp, client, h.Method, uri, h.StatusCode, 0)
}

func (i *FindingContext) forFile(f *types.File) []RelatedEvidence {
	if !f.IsComplete || f.Protocol != "HTTP" || f.FlowDirection != "server_to_client" || f.StreamInitialLossUnknown || f.StreamMissingBytes != 0 {
		return nil
	}
	key, client, server := contextFlow(f.CommunityID, f.SrcIP, f.DstIP, f.SrcPort, f.DstPort)
	links := i.addDNSLink(nil, key, f.Timestamp, client, server, f.Host)
	// Legacy File rows describe the HTTP transaction in Source. Require the
	// exact method, request target, response status and a unique observed match.
	source, ok := strings.CutPrefix(f.Source, "HTTP ")
	if !ok || len(source) > 4128 || f.Host == "" {
		return links
	}
	method, target, ok := strings.Cut(source, " ")
	if !ok || (method != "GET" && method != "POST") {
		return links
	}
	target, statusText, ok := strings.Cut(target, " (Status: ")
	status, err := strconv.ParseInt(strings.TrimSuffix(statusText, ")"), 10, 32)
	uri, name := contextURL(target, f.Host)
	if !ok || !strings.HasSuffix(statusText, ")") || err != nil || name == "" || status < 200 || status >= 300 {
		return links
	}
	return i.appendReferrers(links, key, f.Timestamp, client, method, uri, int32(status), int64(120*time.Second))
}

func (i *FindingContext) appendReferrers(links []RelatedEvidence, key findingFlow, at int64, client netip.Addr, method string, uri findingURL, status int32, window int64) []RelatedEvidence {
	conn := i.connectionAt(key, at, "TCP")
	if conn == nil || uri == (findingURL{}) {
		return links
	}
	var start *findingHTTP
	rows := i.http[key]
	for n := range rows {
		h := &rows[n]
		if h.client != client || h.method != method || h.status != status || h.uri != uri || h.ref.Timestamp > at ||
			at-h.ref.Timestamp > window || i.connectionAt(key, h.ref.Timestamp, "TCP") != conn {
			continue
		}
		if start != nil {
			return links
		}
		start = h
	}
	if start == nil {
		return links
	}
	child := *start
	for range 3 {
		if child.referer == (findingURL{}) {
			break
		}
		parent := i.referrer(child)
		if parent == nil {
			break
		}
		if parent.host != child.host {
			via := child.ref
			links = append(links, RelatedEvidence{Relationship: "http-referrer", Name: parent.host, IP: parent.server.String(), Record: parent.ref, Via: &via})
		}
		child = *parent
	}
	return links
}

func (i *FindingContext) referrer(child findingHTTP) *findingHTTP {
	rows := i.urls[findingURLKey{child.scope, child.client, child.referer}]
	var match *findingHTTP
	for n := range rows {
		r := &rows[n]
		if r.ref.Timestamp >= child.ref.Timestamp || child.ref.Timestamp-r.ref.Timestamp > int64(90*time.Second) {
			continue
		}
		if match != nil {
			return nil
		}
		match = r
	}
	return match
}
