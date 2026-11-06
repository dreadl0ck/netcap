package vulndb

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type CPEMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding,omitempty"`
	StartExcluding string `json:"versionStartExcluding,omitempty"`
	EndIncluding   string `json:"versionEndIncluding,omitempty"`
	EndExcluding   string `json:"versionEndExcluding,omitempty"`
}
type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	Matches  []CPEMatch `json:"cpeMatch,omitempty"`
	Children []Node     `json:"children,omitempty"`
	Nodes    []Node     `json:"nodes,omitempty"`
}
type Configuration struct {
	Operator string `json:"operator,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
	Nodes    []Node `json:"nodes"`
}
type Identity struct{ Part, Vendor, Product, Version string }

func splitCPE(s string) ([]string, bool) {
	var fields []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune('\\')
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			fields = append(fields, b.String())
			b.Reset()
		} else {
			b.WriteRune(r)
		}
	}
	if escaped {
		return nil, false
	}
	fields = append(fields, b.String())
	return fields, len(fields) == 13 && fields[0] == "cpe" && fields[1] == "2.3"
}
func unescapeCPE(s string) string {
	var b strings.Builder
	escape := false
	for _, r := range s {
		if escape {
			b.WriteRune(r)
			escape = false
		} else if r == '\\' {
			escape = true
		} else {
			b.WriteRune(r)
		}
	}
	return strings.ToLower(b.String())
}

func canonicalIdentity(vendor, product, version string) (Identity, bool) {
	norm := func(s string) string { return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), " ", "_") }
	v, p := norm(vendor), norm(product)
	// Display names map only to explicit product identities, never description text.
	aliases := map[string][2]string{"apache": {"apache", "http_server"}, "http_server": {"apache", "http_server"}, "ie": {"microsoft", "internet_explorer"}, "internet_explorer": {"microsoft", "internet_explorer"}, "microsoft-iis": {"microsoft", "internet_information_services"}, "chrome": {"google", "chrome"}, "edge": {"microsoft", "edge"}, "firefox": {"mozilla", "firefox"}, "nginx": {"nginx", "nginx"}, "openssh": {"openbsd", "openssh"}, "postgresql": {"postgresql", "postgresql"}}
	if p == "" {
		if _, ok := aliases[v]; ok {
			p = v
			v = ""
		}
	}
	if alias, ok := aliases[p]; ok {
		if v != "" && v != alias[0] && v != p {
			return Identity{}, false
		}
		v, p = alias[0], alias[1]
	}
	if v == "" || p == "" || version == "" || version == "-" || strings.EqualFold(version, "unknown") || len(version) > 256 || strings.ContainsAny(v+p, "*?\\:") || strings.ContainsAny(version, "*?\\") {
		return Identity{}, false
	}
	return Identity{"a", v, p, version}, true
}

// Three-valued results prevent an unobserved OS/edition prerequisite becoming a match.
type truth uint8

const (
	unknown truth = iota
	no
	yes
)

func combine(op string, children []truth, negate bool) truth {
	if len(children) == 0 {
		return unknown
	}
	if op == "" && len(children) == 1 {
		op = "OR"
	}
	result := unknown
	switch strings.ToUpper(op) {
	case "OR":
		result = no
		for _, c := range children {
			if c == yes {
				result = yes
				break
			}
			if c == unknown {
				result = unknown
			}
		}
	case "AND":
		result = yes
		for _, c := range children {
			if c == no {
				result = no
				break
			}
			if c == unknown {
				result = unknown
			}
		}
	}
	if negate {
		if result == yes {
			return no
		}
		if result == no {
			return yes
		}
	}
	return result
}
func compareVersion(a, b string) (int, bool) {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	if len(x) > 16 || len(y) > 16 {
		return 0, false
	}
	var left, right [16]uint64
	for i, s := range x {
		n, e := strconv.ParseUint(s, 10, 32)
		if e != nil {
			return 0, false
		}
		left[i] = n
	}
	for i, s := range y {
		n, e := strconv.ParseUint(s, 10, 32)
		if e != nil {
			return 0, false
		}
		right[i] = n
	}
	for i := range left {
		if left[i] < right[i] {
			return -1, true
		}
		if left[i] > right[i] {
			return 1, true
		}
	}
	return 0, true
}
func matchCPE(m CPEMatch, id Identity) truth {
	p, ok := splitCPE(m.Criteria)
	if !ok {
		return unknown
	}
	if unescapeCPE(p[2]) != id.Part || unescapeCPE(p[3]) != id.Vendor || unescapeCPE(p[4]) != id.Product {
		return unknown
	}
	if p[5] != "*" && unescapeCPE(p[5]) != strings.ToLower(id.Version) {
		return no
	}
	for _, bound := range []struct {
		value            string
		lower, inclusive bool
	}{{m.StartIncluding, true, true}, {m.StartExcluding, true, false}, {m.EndIncluding, false, true}, {m.EndExcluding, false, false}} {
		if bound.value == "" {
			continue
		}
		cmp, ok := compareVersion(id.Version, bound.value)
		if !ok {
			return unknown
		}
		if bound.lower && (cmp < 0 || cmp == 0 && !bound.inclusive) || !bound.lower && (cmp > 0 || cmp == 0 && !bound.inclusive) {
			return no
		}
	}
	for _, attribute := range p[6:] {
		if attribute != "*" {
			return unknown
		}
	}
	return yes
}
func evalNode(n Node, id Identity, depth int) (truth, bool) {
	if depth > 16 {
		return unknown, false
	}
	var children []truth
	affected := false
	for _, m := range n.Matches {
		value := matchCPE(m, id)
		children = append(children, value)
		if m.Vulnerable && value == yes {
			affected = true
		}
	}
	for _, child := range append(append([]Node(nil), n.Children...), n.Nodes...) {
		v, a := evalNode(child, id, depth+1)
		children = append(children, v)
		affected = affected || a
	}
	result := combine(n.Operator, children, n.Negate)
	if n.Negate || result != yes {
		affected = false
	}
	return result, affected
}
func applicable(configs []Configuration, id Identity) bool {
	for _, c := range configs {
		var children []truth
		affected := false
		for _, n := range c.Nodes {
			v, a := evalNode(n, id, 0)
			children = append(children, v)
			affected = affected || a
		}
		if !c.Negate && affected && combine(c.Operator, children, false) == yes {
			return true
		}
	}
	return false
}
func configurationProducts(configs []Configuration) []Identity {
	seen := map[string]bool{}
	var out []Identity
	budget := 10000
	var visit func(Node, int)
	visit = func(n Node, depth int) {
		if depth > 16 || budget <= 0 {
			return
		}
		budget--
		for _, m := range n.Matches {
			if !m.Vulnerable {
				continue
			}
			p, ok := splitCPE(m.Criteria)
			if !ok || p[2] == "*" || p[3] == "*" || p[4] == "*" {
				continue
			}
			id := Identity{Part: unescapeCPE(p[2]), Vendor: unescapeCPE(p[3]), Product: unescapeCPE(p[4])}
			key := id.Part + ":" + id.Vendor + ":" + id.Product
			if !seen[key] {
				seen[key] = true
				out = append(out, id)
			}
		}
		for _, child := range n.Children {
			visit(child, depth+1)
		}
		for _, child := range n.Nodes {
			visit(child, depth+1)
		}
	}
	for _, c := range configs {
		for _, n := range c.Nodes {
			visit(n, 0)
		}
	}
	return out
}

func (d *DB) Vulnerabilities(vendor, product, version string) ([]Vulnerability, error) {
	id, ok := canonicalIdentity(vendor, product, version)
	if !ok {
		return nil, nil
	}
	rows, err := d.db.Query(`SELECT n.id,n.description,n.severity,n.v2_score,n.access_vector,n.attack_complexity,n.confidentiality_impact,n.integrity_impact,n.availability_impact,n.base_score,n.base_severity,n.configurations FROM nvd n JOIN nvd_products p ON p.nvd_rowid=n.rowid WHERE p.part=? AND p.vendor=? AND p.product=? ORDER BY n.id`, id.Part, id.Vendor, id.Product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var raw string
		if err := rows.Scan(&v.ID, &v.Description, &v.Severity, &v.V2Score, &v.AccessVector, &v.AttackComplexity, &v.ConfidentialityImpact, &v.IntegrityImpact, &v.AvailabilityImpact, &v.BaseScore, &v.BaseSeverity, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &v.Configurations); err != nil {
			return nil, fmt.Errorf("invalid stored applicability: %w", err)
		}
		if applicable(v.Configurations, id) {
			v.MatchStatus = "cpe-product-version"
			result = append(result, v)
			if len(result) == MaxHits {
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range result {
		result[i].References, err = d.References(result[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// Exploit associations require a CVE whose CPE applicability matches this software.
func (d *DB) Exploits(vendor, product, version string) ([]Exploit, error) {
	vulns, err := d.Vulnerabilities(vendor, product, version)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var result []Exploit
	for _, v := range vulns {
		rows, err := d.db.Query(`SELECT e.id,e.file,e.description,e.date,e.author,e.type,e.platform,e.port FROM exploits e JOIN exploit_cves c ON c.exploit_id=e.id WHERE c.cve_id=? ORDER BY e.id`, v.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e Exploit
			if err := rows.Scan(&e.ID, &e.File, &e.Description, &e.Date, &e.Author, &e.Type, &e.Platform, &e.Port); err != nil {
				rows.Close()
				return nil, err
			}
			if !seen[e.ID] {
				seen[e.ID] = true
				e.CVEs = []string{v.ID}
				e.MatchStatus = "references-applicable-cve"
				result = append(result, e)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > MaxHits {
		result = result[:MaxHits]
	}
	return result, nil
}
