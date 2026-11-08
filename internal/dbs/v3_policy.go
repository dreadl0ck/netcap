package dbs

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

const (
	V3Layout      = 3
	VulnDBSchema  = vulndb.SchemaVersion
	CandidateFile = "SOURCE_CANDIDATE.json"
	ManifestFile  = "RELEASE_MANIFEST.json"
)

// CandidateFiles is a copy of the positive publication policy. Presence here
// permits review; it is not a redistribution grant.
func CandidateFiles() map[string]string {
	return map[string]string{
		resolvers.ManagedPopularityFile: "netapi",
		"netcap.sqlite":                 "nvd", "hasshdb.json": "hassh",
		"regexes.yaml": "ua-parser", "service-names-port-numbers.csv": "iana",
		"dbip-city-lite.mmdb": "dbip", "dbip-asn-lite.mmdb": "dbip",
		"geoip-sources.json":      "dbip",
		"service-signatures.json": "netcap-service-signatures",
	}
}

// SourceEvidence describes the actual snapshot and transformation, without
// implying that its rights have been reviewed. GrantText must contain the full
// applicable terms; NoticeText includes copyright and upstream acknowledgements.
type SourceEvidence struct {
	ID             string     `json:"id"`
	Origin         string     `json:"origin"`
	Revision       string     `json:"revision"`
	SHA256         string     `json:"sha256"`
	Transformation string     `json:"transformation"`
	GrantText      string     `json:"grant_text"`
	GrantSHA256    string     `json:"grant_sha256"`
	NoticeText     string     `json:"notice_text"`
	GrantOrigin    string     `json:"grant_origin"`
	GrantRevision  string     `json:"grant_revision"`
	NVDInputs      []NVDInput `json:"nvd_inputs,omitempty"`
}

type NVDInput struct {
	Year   int    `json:"year"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type ReleaseFile struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Candidate struct {
	Layout       int              `json:"layout"`
	VulnDBSchema int              `json:"vulndb_schema"`
	Files        []ReleaseFile    `json:"files"`
	Sources      []SourceEvidence `json:"sources"`
}

// ReviewedSource is supplied separately by an operator's rights-review process.
// The generator never creates these records. Outputs scope the exact bytes
// permitted by that review, including derived SQLite and provenance files.
type ReviewedSource struct {
	Evidence   SourceEvidence `json:"evidence"`
	Outputs    []ReleaseFile  `json:"outputs"`
	Decision   string         `json:"decision"`
	Reviewer   string         `json:"reviewer"`
	ReviewID   string         `json:"review_id"`
	ReviewedAt string         `json:"reviewed_at"`
}

type ReleaseManifest struct {
	Candidate
	Reviews                []ReviewedSource `json:"reviews"`
	ApprovalRegistrySHA256 string           `json:"approval_registry_sha256"`
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func readJSON(path string, dst any) error {
	b, err := readRegularBytes(path, 16<<20)
	if err != nil {
		return err
	}
	return decodeJSON(b, dst)
}

func decodeJSON(b []byte, dst any) error {
	unique := json.NewDecoder(bytes.NewReader(b))
	if err := uniqueJSONValue(unique, 0); err != nil {
		return err
	}
	if _, err := unique.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func uniqueJSONValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON evidence nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid JSON evidence key %v", key)
			}
			seen[name] = true
			if err := uniqueJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON evidence object")
		}
	case '[':
		for d.More() {
			if err := uniqueJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON evidence array")
		}
	default:
		return fmt.Errorf("unexpected JSON evidence delimiter")
	}
	return nil
}

func scanCandidate(dir string) ([]ReleaseFile, error) {
	root, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("candidate root must be a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []ReleaseFile
	allowed := CandidateFiles()
	for _, entry := range entries {
		name := entry.Name()
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("non-regular candidate member %q", name)
		}
		if name == CandidateFile {
			continue
		}
		if name == "DATABASE_NOTICES.txt" {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(b, databaseNotices) {
				return nil, fmt.Errorf("stale database notices")
			}
			continue
		}
		source, ok := allowed[name]
		if !ok {
			return nil, fmt.Errorf("publication policy rejects member %q (including stale derived data)", name)
		}
		sum, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files = append(files, ReleaseFile{name, source, sum, size})
	}
	return files, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := openRegular(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// WriteCandidate records unapproved evidence for review, never an approval.
func WriteCandidate(dir string, evidence []SourceEvidence) error {
	files, err := scanCandidate(dir)
	if err != nil {
		return err
	}
	c := Candidate{V3Layout, VulnDBSchema, files, evidence}
	return atomicJSON(filepath.Join(dir, CandidateFile), c)
}

func validateManifest(m ReleaseManifest) error {
	if !validDigest(m.ApprovalRegistrySHA256) {
		return fmt.Errorf("missing pinned operator registry identity")
	}
	if m.Layout != V3Layout || m.VulnDBSchema != VulnDBSchema {
		return fmt.Errorf("unsupported release layout/schema")
	}
	if len(m.Files) == 0 || len(m.Sources) == 0 || len(m.Reviews) != len(m.Sources) {
		return fmt.Errorf("missing files or explicit reviewed records")
	}
	sources := map[string]SourceEvidence{}
	for _, s := range m.Sources {
		if _, exists := sources[s.ID]; exists {
			return fmt.Errorf("duplicate source %q", s.ID)
		}
		if err := validateEvidence(s); err != nil {
			return err
		}
		sources[s.ID] = s
	}
	files := map[string]ReleaseFile{}
	bySource := map[string][]ReleaseFile{}
	for _, f := range m.Files {
		if CandidateFiles()[f.Path] != f.Source || f.Source == "" || !validDigest(f.SHA256) || f.Size <= 0 {
			return fmt.Errorf("invalid release member %q", f.Path)
		}
		if _, exists := files[f.Path]; exists {
			return fmt.Errorf("duplicate member %q", f.Path)
		}
		if _, exists := sources[f.Source]; !exists {
			return fmt.Errorf("unreviewed source %q", f.Source)
		}
		files[f.Path] = f
		bySource[f.Source] = append(bySource[f.Source], f)
	}
	if _, ok := files["netcap.sqlite"]; !ok {
		return fmt.Errorf("release requires NVD-only netcap.sqlite")
	}
	seen := map[string]bool{}
	for _, r := range m.Reviews {
		if err := validateReview(r); err != nil {
			return err
		}
		id := r.Evidence.ID
		if seen[id] || r.Decision != "approved-for-publication" || r.Reviewer == "" || r.ReviewID == "" {
			return fmt.Errorf("missing explicit rights review for %q", id)
		}
		if _, err := time.Parse(time.RFC3339, r.ReviewedAt); err != nil {
			return fmt.Errorf("invalid review timestamp for %q", id)
		}
		if !reflect.DeepEqual(sources[id], r.Evidence) || len(bySource[id]) == 0 {
			return fmt.Errorf("changed or unused source evidence %q", id)
		}
		want := append([]ReleaseFile(nil), bySource[id]...)
		got := append([]ReleaseFile(nil), r.Outputs...)
		sort.Slice(want, func(i, j int) bool { return want[i].Path < want[j].Path })
		sort.Slice(got, func(i, j int) bool { return got[i].Path < got[j].Path })
		if !reflect.DeepEqual(want, got) {
			return fmt.Errorf("changed output scope for %q", id)
		}
		seen[id] = true
	}
	return nil
}

func validateEvidence(s SourceEvidence) error {
	for _, v := range []string{s.ID, s.Origin, s.Revision, s.Transformation, s.GrantText, s.NoticeText, s.GrantOrigin, s.GrantRevision} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("incomplete source/grant acquisition evidence for %q", s.ID)
		}
	}
	if !validDigest(s.SHA256) || digest([]byte(s.GrantText)) != s.GrantSHA256 {
		return fmt.Errorf("invalid source/grant hash for %s", s.ID)
	}
	if s.ID == "nvd" {
		if err := validateNVDInputs(s.NVDInputs); err != nil {
			return err
		}
		if nvdInputDigest(s.NVDInputs) != s.SHA256 {
			return fmt.Errorf("NVD year inventory hash mismatch")
		}
	} else if len(s.NVDInputs) != 0 {
		return fmt.Errorf("NVD inputs on non-NVD source")
	}
	return nil
}

func validateReview(r ReviewedSource) error {
	if err := validateEvidence(r.Evidence); err != nil {
		return err
	}
	if r.Decision != "approved-for-publication" || strings.TrimSpace(r.Reviewer) == "" || strings.TrimSpace(r.ReviewID) == "" {
		return fmt.Errorf("explicit publication review required")
	}
	if _, err := time.Parse(time.RFC3339, r.ReviewedAt); err != nil {
		return fmt.Errorf("invalid review timestamp")
	}
	if len(r.Outputs) == 0 {
		return fmt.Errorf("review has no exact output scope")
	}
	seen := map[string]bool{}
	for _, f := range r.Outputs {
		if seen[f.Path] || f.Source != r.Evidence.ID || CandidateFiles()[f.Path] != f.Source || !validDigest(f.SHA256) || f.Size <= 0 {
			return fmt.Errorf("invalid exact reviewed output scope")
		}
		seen[f.Path] = true
	}
	return nil
}

// VerifyCandidate is shared by generator, nightly and manual publication.
// approvalsPath is an explicitly supplied, separate reviewed-record file.
func VerifyCandidate(dir, approvalsPath string) (ReleaseManifest, error) {
	trust, err := loadApprovalTrust(approvalsPath, os.Getenv(ApprovalRegistryPinEnv), dir)
	if err != nil {
		return ReleaseManifest{}, err
	}
	return verifyCandidateWithTrust(dir, trust)
}

func verifyCandidateWithTrust(dir string, trust approvalTrust) (ReleaseManifest, error) {
	var c Candidate
	var reviews []ReviewedSource
	if err := readJSON(filepath.Join(dir, CandidateFile), &c); err != nil {
		return ReleaseManifest{}, err
	}
	for _, source := range c.Sources {
		if source.ID == "nvd" && (len(source.NVDInputs) == 0 || source.NVDInputs[len(source.NVDInputs)-1].Year != time.Now().Year()) {
			return ReleaseManifest{}, fmt.Errorf("publication requires every NVD year through the current year")
		}
	}
	for _, source := range c.Sources {
		var outputs []ReleaseFile
		for _, f := range c.Files {
			if f.Source == source.ID {
				outputs = append(outputs, f)
			}
		}
		for _, r := range trust.Reviews {
			if !reflect.DeepEqual(r.Evidence, source) {
				continue
			}
			want, got := append([]ReleaseFile(nil), outputs...), append([]ReleaseFile(nil), r.Outputs...)
			sort.Slice(want, func(i, j int) bool { return want[i].Path < want[j].Path })
			sort.Slice(got, func(i, j int) bool { return got[i].Path < got[j].Path })
			if reflect.DeepEqual(want, got) {
				reviews = append(reviews, r)
				break
			}
		}
	}
	m := ReleaseManifest{Candidate: c, Reviews: reviews, ApprovalRegistrySHA256: trust.SHA256}
	if err := trust.authorize(m); err != nil {
		return m, err
	}
	actual, err := scanCandidate(dir)
	if err != nil {
		return m, err
	}
	if !reflect.DeepEqual(actual, c.Files) {
		return m, fmt.Errorf("candidate files changed after evidence capture")
	}
	if err := validateReleaseData(dir); err != nil {
		return m, err
	}
	if err := validateSourceBindings(dir, m); err != nil {
		return m, err
	}
	return m, nil
}

func validateSourceBindings(dir string, m ReleaseManifest) error {
	for _, source := range m.Sources {
		var observed string
		switch source.ID {
		case "nvd":
			db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
			if err != nil {
				return err
			}
			meta, err := db.Meta()
			db.Close()
			if err != nil {
				return err
			}
			observed = meta["input_sha256"]
			var inputs []NVDInput
			if err := decodeJSON([]byte(meta["nvd_inputs"]), &inputs); err != nil {
				return err
			}
			if !reflect.DeepEqual(inputs, source.NVDInputs) {
				return fmt.Errorf("SQLite per-year NVD snapshot inventory mismatch")
			}
			if err := validateNVDInputs(inputs); err != nil {
				return err
			}
			if meta["nvd_start_year"] != fmt.Sprint(inputs[0].Year) || meta["nvd_end_year"] != fmt.Sprint(inputs[len(inputs)-1].Year) {
				return fmt.Errorf("SQLite NVD year coverage mismatch")
			}
		case "dbip":
			sum, _, err := hashFile(filepath.Join(dir, "geoip-sources.json"))
			if err != nil {
				return err
			}
			observed = sum
		default:
			for _, file := range m.Files {
				if file.Source == source.ID {
					observed = file.SHA256
				}
			}
		}
		if !validDigest(observed) || observed != source.SHA256 {
			return fmt.Errorf("source snapshot binding mismatch for %s", source.ID)
		}
	}
	return nil
}

func validateReleaseData(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, resolvers.ManagedPopularityFile)); err == nil {
		if _, _, err := resolvers.LoadManagedDomainPopularityList(dir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, servicesignatures.FileName)); err == nil {
		f, err := openRegular(filepath.Join(dir, servicesignatures.FileName))
		if err != nil {
			return err
		}
		_, err = servicesignatures.Parse(f)
		f.Close()
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := validateGeoIPBundle(dir); err != nil {
		return err
	}
	db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
	if err != nil {
		return err
	}
	defer db.Close()
	meta, err := db.Meta()
	if err != nil {
		return err
	}
	if meta["exploit_count"] != "0" || meta["publication_profile"] != "nvd-only-v3" || meta["nvd_count"] == "0" {
		return fmt.Errorf("SQLite is not a fresh NVD-only v3 build")
	}
	abs, err := filepath.Abs(filepath.Join(dir, "netcap.sqlite"))
	if err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", "file:"+filepath.ToSlash(abs)+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer conn.Close()
	var exploits, nvd int
	if err := conn.QueryRow("SELECT count(*) FROM exploits").Scan(&exploits); err != nil {
		return err
	}
	if err := conn.QueryRow("SELECT count(*) FROM nvd").Scan(&nvd); err != nil {
		return err
	}
	if exploits != 0 || nvd == 0 {
		return fmt.Errorf("SQLite contains unapproved exploit data or no NVD entries")
	}
	var integrity string
	if err := conn.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("SQLite integrity: %s", integrity)
	}
	return nil
}

func validateMetadataCoverage(dir string, m *DBMetadata) error {
	db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
	if err != nil {
		return err
	}
	defer db.Close()
	values, err := db.Meta()
	if err != nil {
		return err
	}
	if values["nvd_start_year"] != fmt.Sprint(m.NVDStartYear) || values["nvd_end_year"] != fmt.Sprint(m.NVDEndYear) {
		return fmt.Errorf("NVD coverage metadata mismatch")
	}
	return nil
}

func atomicJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicBytes(path, append(b, '\n'))
}

func atomicBytes(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return replaceAtomicFile(f.Name(), path)
}
