package enrichment

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

const KEVRevision = "7411529f9cf070b9c13a965fc6f3314a6b630c14"
const KEVOrigin = "https://github.com/cisagov/kev-data"
const KEVInputSHA256 = "273b7e449828f0af92e012bf03270a6a6c3deb21dc7a50b46ebe0447ea196bff"
const KEVGrantSHA256 = "8dfcf2d0cba33bede386eb470daf2ac08caf6540fc2516baab10dd546f90938a"
const KEVFormat = "netcap-kev/v1"

func BuildKEVFiles(inputPath, grantPath string) ([]byte, Source, error) {
	input, e := regular(inputPath, MaxMember)
	if e != nil {
		return nil, Source{}, e
	}
	grant, e := regular(grantPath, 64<<10)
	if e != nil {
		return nil, Source{}, e
	}
	return BuildKEV(input, grant)
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
var urlPattern = regexp.MustCompile(`https?://[^\s;<>"']+`)

// KEVStatus describes CISA's catalog assertion, never a new software/CVE match.
// FederalDueDate is CISA's federal remediation deadline, not a universal customer deadline.
type KEVStatus struct {
	CVE            string   `json:"cve"`
	DateAdded      string   `json:"date_added"`
	Ransomware     string   `json:"ransomware"`
	FederalDueDate string   `json:"federal_due_date"`
	RequiredAction string   `json:"required_action"`
	URLs           []string `json:"urls"`
}
type KEVCatalog struct {
	Format         string      `json:"format"`
	CatalogVersion string      `json:"catalog_version"`
	DateReleased   string      `json:"date_released"`
	Count          int         `json:"count"`
	Entries        []KEVStatus `json:"entries"`
}

func validDate(s string) bool {
	t, e := time.Parse("2006-01-02", s)
	return e == nil && t.Format("2006-01-02") == s
}
func ParseKEV(b []byte) (*KEVCatalog, error) {
	if len(b) > MaxMember {
		return nil, fmt.Errorf("oversized KEV catalog")
	}
	var c KEVCatalog
	if e := decode(b, &c); e != nil {
		return nil, e
	}
	if c.Format != KEVFormat || c.Count <= 0 || c.Count > 100000 || c.Count != len(c.Entries) || c.CatalogVersion == "" {
		return nil, fmt.Errorf("invalid KEV format/count")
	}
	if _, e := time.Parse(time.RFC3339Nano, c.DateReleased); e != nil {
		return nil, e
	}
	last := ""
	for _, s := range c.Entries {
		if !cvePattern.MatchString(s.CVE) || s.CVE <= last || !validDate(s.DateAdded) || !validDate(s.FederalDueDate) || (s.Ransomware != "Known" && s.Ransomware != "Unknown") || len(s.RequiredAction) > 16384 || s.RequiredAction == "" || s.URLs == nil || len(s.URLs) > 32 {
			return nil, fmt.Errorf("invalid/duplicate KEV entry %s", s.CVE)
		}
		last = s.CVE
		prev := ""
		for _, raw := range s.URLs {
			u, e := url.Parse(raw)
			if e != nil || len(raw) > 2048 || strings.Contains(raw, `\`) || strings.IndexFunc(raw, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || raw <= prev {
				return nil, fmt.Errorf("invalid KEV reference")
			}
			prev = raw
		}
	}
	return &c, nil
}
func (c *KEVCatalog) Lookup(cve string) *KEVStatus {
	if c == nil || !cvePattern.MatchString(cve) {
		return nil
	}
	i := sort.Search(len(c.Entries), func(i int) bool { return c.Entries[i].CVE >= cve })
	if i == len(c.Entries) || c.Entries[i].CVE != cve {
		return nil
	}
	s := c.Entries[i]
	s.URLs = append([]string{}, s.URLs...)
	return &s
}

// BuildKEV transforms the pinned JSON only. It neither acquires PoCs nor follows reference URLs.
func BuildKEV(input, grant []byte) ([]byte, Source, error) {
	if Digest(input) != KEVInputSHA256 {
		return nil, Source{}, fmt.Errorf("changed historical KEV input")
	}
	return BuildKEVSnapshot(input, grant, KEVRevision, KEVInputSHA256)
}

func BuildKEVSnapshotFiles(inputPath, grantPath, revision, inputHash string) ([]byte, Source, error) {
	input, e := regular(inputPath, MaxMember)
	if e != nil {
		return nil, Source{}, e
	}
	grant, e := regular(grantPath, 64<<10)
	if e != nil {
		return nil, Source{}, e
	}
	return BuildKEVSnapshot(input, grant, revision, inputHash)
}

// BuildKEVSnapshot admits a freshly acquired immutable GitHub revision, retaining exact input and unchanged CC0 grant pins.
func BuildKEVSnapshot(input, grant []byte, revision, inputHash string) ([]byte, Source, error) {
	var source Source
	var in struct {
		Title           string `json:"title"`
		Version         string `json:"catalogVersion"`
		Released        string `json:"dateReleased"`
		Count           int    `json:"count"`
		Vulnerabilities []struct {
			CVE         string   `json:"cveID"`
			Vendor      string   `json:"vendorProject"`
			Product     string   `json:"product"`
			Name        string   `json:"vulnerabilityName"`
			Added       string   `json:"dateAdded"`
			Description string   `json:"shortDescription"`
			Action      string   `json:"requiredAction"`
			Due         string   `json:"dueDate"`
			Ransomware  string   `json:"knownRansomwareCampaignUse"`
			Triage      string   `json:"forensicTriage"`
			Notes       string   `json:"notes"`
			CWEs        []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}
	if len(revision) != 40 || strings.Trim(revision, "0123456789abcdef") != "" || !validDigest(inputHash) || len(input) > MaxMember || Digest(input) != inputHash || Digest(grant) != KEVGrantSHA256 || decode(input, &in) != nil {
		return nil, source, fmt.Errorf("invalid or changed pinned KEV input/grant")
	}
	if in.Count < 1 || in.Count > 100000 || len(in.Vulnerabilities) != in.Count || in.Version == "" || !strings.Contains(string(grant), "CC0 1.0 Universal") || len(grant) < 6000 {
		return nil, source, fmt.Errorf("pinned KEV snapshot/count or full CC0 grant mismatch")
	}
	c := KEVCatalog{Format: KEVFormat, CatalogVersion: in.Version, DateReleased: in.Released, Count: in.Count}
	for _, v := range in.Vulnerabilities {
		urls := urlPattern.FindAllString(v.Notes, -1)
		set := map[string]bool{}
		for _, u := range urls {
			set[u] = true
		}
		urls = []string{}
		for u := range set {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		c.Entries = append(c.Entries, KEVStatus{v.CVE, v.Added, v.Ransomware, v.Due, v.Action, urls})
	}
	sort.Slice(c.Entries, func(i, j int) bool { return c.Entries[i].CVE < c.Entries[j].CVE })
	b, e := json.Marshal(c)
	if e != nil {
		return nil, source, e
	}
	if _, e = ParseKEV(b); e != nil {
		return nil, source, e
	}
	source = Source{ID: "cisa-kev", Origin: KEVOrigin, Revision: revision, InputSHA256: Digest(input), GrantOrigin: KEVOrigin + "/blob/" + revision + "/LICENSE", GrantRevision: revision, GrantText: string(grant), GrantSHA256: Digest(grant), Transformation: "netcap-kev-v1: strict pinned JSON; unique sorted CVEs; CISA dates/actions/ransomware labels; bounded HTTP(S) references only", Outputs: []File{{"kev.json", Digest(b), int64(len(b))}}}
	return b, source, nil
}
