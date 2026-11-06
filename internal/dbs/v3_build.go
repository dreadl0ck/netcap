package dbs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

func jsonResponse(w http.ResponseWriter, value any) error { return json.NewEncoder(w).Encode(value) }

func NewDBServerWithRegistry(addr string, year int, verbose bool, path, pin string) *DBServer {
	s := NewDBServer(addr, year, verbose)
	s.approvalPath, s.approvalPin, s.approvalConfigured = path, pin, true
	return s
}

func (s *DBServer) approvalRegistry() (string, string) {
	if s.approvalConfigured {
		return s.approvalPath, s.approvalPin
	}
	return os.Getenv(ApprovalRegistryEnv), os.Getenv(ApprovalRegistryPinEnv)
}

func (s *DBServer) approvalTrust() (approvalTrust, error) {
	path, pin := s.approvalRegistry()
	return loadApprovalTrust(path, pin, s.dbsDir)
}

// BuildCandidate always uses new inputs. An incomplete fetch/index is an error;
// existing releases and ambient database directories are never used as inputs.
// The returned directory is deliberately unapproved and retained for review.
func BuildCandidate(root string, startYear int) (string, error) {
	return buildCandidate(root, startYear, os.Getenv("NC_DBS_APPROVALS"))
}

func buildCandidate(root string, startYear int, approvalsPath string) (string, error) {
	return buildCandidatePinned(root, startYear, approvalsPath, os.Getenv(ApprovalRegistryPinEnv))
}

func buildCandidatePinned(root string, startYear int, approvalsPath, registrySHA256 string) (string, error) {
	if startYear == 0 {
		startYear = 2002
	}
	if startYear < 2002 || startYear > time.Now().Year() {
		return "", fmt.Errorf("invalid NVD start year")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	base, err := os.MkdirTemp(root, "candidate-*")
	if err != nil {
		return "", err
	}
	build, dir := filepath.Join(base, "build"), filepath.Join(base, "dbs")
	for _, p := range []string{build, dir} {
		if err := os.Mkdir(p, 0o755); err != nil {
			return "", err
		}
	}
	var evidence []SourceEvidence
	for _, s := range sources {
		if s.name == "nvd" {
			continue
		}
		if _, skip := skippedSourceNames()[s.name]; skip {
			continue
		}
		path := filepath.Join(build, s.name)
		if err := fetchResource(s, path); err != nil {
			return "", err
		}
		sum, _, err := hashFile(path)
		if err != nil {
			return "", err
		}
		if err := moveToDbs(path, s, base); err != nil {
			return "", err
		}
		evidence = append(evidence, SourceEvidence{ID: CandidateFiles()[s.name], Origin: s.url, Revision: sum, SHA256: sum, Transformation: "byte-for-byte"})
	}
	for _, year := range yearRange(startYear, time.Now().Year()) {
		url := "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-" + year + ".json.gz"
		path := filepath.Join(build, "nvdcve-2.0-"+year+".json.gz")
		if err := fetchResource(makeSource(url, "", nil), path); err != nil {
			return "", fmt.Errorf("required NVD year %s: %w", year, err)
		}
	}
	if err := BuildVulnDB(build, dir, startYear, false); err != nil {
		return "", err
	}
	db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
	if err != nil {
		return "", err
	}
	values, err := db.Meta()
	db.Close()
	if err != nil {
		return "", err
	}
	var nvdInputs []NVDInput
	if err := decodeJSON([]byte(values["nvd_inputs"]), &nvdInputs); err != nil {
		return "", err
	}
	sum := values["input_sha256"]
	evidence = append(evidence, SourceEvidence{ID: "nvd", Origin: "https://nvd.nist.gov/feeds/json/cve/2.0/", Revision: strconv.Itoa(startYear) + "-" + values["nvd_end_year"] + ":" + sum, SHA256: sum, Transformation: "netcap-nvd-v3.4: frozen complete NVD 2.0 yearly gzip inputs, NVD-only SQLite schema 1 with nvd_rowid_alias_version=1 valid version foreign key and nvd_references_version=1 HTTP(S) link metadata, sorted metadata without wall-clock fields", NVDInputs: nvdInputs})
	if err := includeDBIP(base, filepath.Join(base, "geoip-cache")); err != nil {
		return "", err
	}
	geo, err := os.ReadFile(filepath.Join(dir, "geoip-sources.json"))
	if err != nil {
		return "", err
	}
	sum = digest(geo)
	evidence = append(evidence, SourceEvidence{ID: "dbip", Origin: "https://db-ip.com/db/lite.php", Revision: sum, SHA256: sum, Transformation: "DB-IP Lite City and ASN gunzip, geoip-sources.json with upstream URLs and content hashes"})
	// Review records may supply grant text, but never change the observed
	// origin, snapshot hash, revision or transformation.
	var reviews []ReviewedSource
	if path := approvalsPath; path != "" {
		trust, err := loadApprovalTrust(path, registrySHA256, base)
		if err != nil {
			return "", err
		}
		reviews = trust.Reviews
		for i, e := range evidence {
			for _, r := range reviews {
				s := r.Evidence
				if e.ID == s.ID && e.Origin == s.Origin && e.Revision == s.Revision && e.SHA256 == s.SHA256 && e.Transformation == s.Transformation && reflect.DeepEqual(e.NVDInputs, s.NVDInputs) {
					evidence[i] = s
				}
			}
		}
	}
	if err := WriteCandidate(dir, evidence); err != nil {
		return "", err
	}
	log.Printf("Unapproved dataset candidate retained at %s; explicit snapshot/output rights reviews required", dir)
	return dir, nil
}

func GenerateDBs(startYear int) error {
	return GenerateDBsWithApprovals(startYear, os.Getenv("NC_DBS_APPROVALS"))
}

func GenerateDBsWithApprovals(startYear int, approvalsPath string) error {
	return GenerateDBsWithRegistry(startYear, approvalsPath, os.Getenv(ApprovalRegistryPinEnv))
}

func GenerateDBsWithRegistry(startYear int, approvalsPath, registrySHA256 string) error {
	dir, err := buildCandidatePinned("netcap-dbs-generated", startYear, approvalsPath, registrySHA256)
	if err != nil {
		return err
	}
	_, err = PackV3WithRegistry(dir, filepath.Join("netcap-dbs-generated", "v3"), approvalsPath, registrySHA256)
	return err
}

func (s *DBServer) rebuildDatabases() (err error) {
	s.mu.Lock()
	s.lastBuildAttempt = time.Now().Format("2006-01-02")
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.lastBuildError = ""
		if err != nil {
			s.lastBuildError = err.Error()
		}
	}()
	path, pin := s.approvalRegistry()
	dir, err := buildCandidatePinned(filepath.Join(s.buildDir, "candidates"), s.nvdStartYear, path, pin)
	if err != nil {
		return err
	}
	meta, err := PackV3WithRegistry(dir, s.dbsDir, path, pin)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.currentDate = meta.Version
	if s.validated == nil {
		s.validated = map[string]DBMetadata{}
	}
	s.validated[meta.Version] = *meta
	s.mu.Unlock()
	s.ready.Store(true)
	return nil
}

// initialize only serves an already validated v3 release. A fresh host never
// imports the resolver's ambient datasets or rebuilds as a startup side effect.
func (s *DBServer) initialize() error {
	trust, err := s.approvalTrust()
	if err != nil {
		return err
	}
	var meta DBMetadata
	if err := readJSON(filepath.Join(s.dbsDir, "latest.json"), &meta); err != nil {
		return err
	}
	if err := validateV3Metadata(&meta); err != nil {
		return err
	}
	if err := verifyV3ArchiveWithTrust(filepath.Join(s.dbsDir, meta.Tarball), &meta, trust); err != nil {
		return err
	}
	var immutable DBMetadata
	if err := readJSON(filepath.Join(s.dbsDir, meta.Version+".json"), &immutable); err != nil {
		return err
	}
	if immutable != meta {
		return fmt.Errorf("latest and immutable metadata differ")
	}
	s.mu.Lock()
	s.currentDate = meta.Version
	s.validated = map[string]DBMetadata{meta.Version: meta}
	s.mu.Unlock()
	// Keep prior digest URLs available across a latest-pointer update. Each
	// cached revision is independently verified before becoming addressable.
	entries, err := os.ReadDir(s.dbsDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !validDigest(strings.TrimSuffix(name, ".json")) || name == meta.Version+".json" {
			continue
		}
		var old DBMetadata
		if err := readJSON(filepath.Join(s.dbsDir, name), &old); err != nil || validateV3Metadata(&old) != nil || old.Version+".json" != name {
			continue
		}
		if err := verifyV3ArchiveWithTrust(filepath.Join(s.dbsDir, old.Tarball), &old, trust); err != nil {
			log.Printf("Ignoring invalid cached v3 revision %s: %v", name, err)
			continue
		}
		s.mu.Lock()
		s.validated[old.Version] = old
		s.mu.Unlock()
	}
	s.ready.Store(true)
	return nil
}

func (s *DBServer) Start() error {
	if err := s.initialize(); err != nil {
		log.Printf("v3 release unavailable (serve-only startup): %v", err)
	}
	if os.Getenv("NC_DBS_REBUILD") == "1" {
		go s.scheduleDailyRebuild()
	}
	return http.ListenAndServe(s.addr, s.Handler())
}

// Handler returns an isolated mux, also usable by hermetic HTTP tests.
func (s *DBServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/dbs/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/dbs/v3/") {
			s.handleLegacy(w, r)
			return
		}
		if !s.ready.Load() {
			http.Error(w, "validated v3 release unavailable", http.StatusServiceUnavailable)
			return
		}
		s.mu.RLock()
		version := s.currentDate
		s.mu.RUnlock()
		name := strings.TrimPrefix(r.URL.Path, "/dbs/v3/")
		id := version
		if strings.HasSuffix(name, ".tar.gz") {
			id = strings.TrimSuffix(name, ".tar.gz")
		}
		if strings.HasSuffix(name, ".json") {
			id = strings.TrimSuffix(name, ".json")
		}
		s.mu.RLock()
		meta, ok := s.validated[id]
		s.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		trust, err := s.approvalTrust()
		if err != nil || meta.ApprovalRegistrySHA256 != trust.SHA256 {
			http.Error(w, "operator rights trust unavailable", 503)
			return
		}
		switch name {
		case "latest", meta.Version + ".json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if name != "latest" {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			_ = jsonResponse(w, meta)
		case "list":
			w.Header().Set("Content-Type", "application/json")
			_ = jsonResponse(w, map[string]any{"latest": version, "versions": []string{version}})
		case meta.Tarball:
			serveVerifiedObject(w, r, filepath.Join(s.dbsDir, meta.Tarball), meta)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

func serveVerifiedObject(w http.ResponseWriter, r *http.Request, path string, meta DBMetadata) {
	w.Header().Set("Cache-Control", "no-store")
	f, err := openRegular(path)
	if err != nil {
		http.Error(w, "verified archive unavailable", 503)
		return
	}
	defer f.Close()
	// Serve a private verified snapshot, never reopen the mutable cache path
	// after hashing or stream an inode another publisher may replace/write.
	snapshot, err := os.CreateTemp("", "netcap-serve-*")
	if err != nil {
		http.Error(w, "verified archive unavailable", 503)
		return
	}
	defer os.Remove(snapshot.Name())
	defer snapshot.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(hash, snapshot), io.LimitReader(f, meta.Size+1))
	if err != nil || n != meta.Size || hex.EncodeToString(hash.Sum(nil)) != meta.SHA256 {
		http.Error(w, "verified archive changed", 503)
		return
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "verified archive unavailable", 503)
		return
	}
	w.Header().Set("ETag", `"`+meta.SHA256+`"`)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeContent(w, r, meta.Tarball, time.Time{}, snapshot)
}

func (s *DBServer) createTarball(dir, target string) (string, int64, error) {
	root, err := canonicalPath(dir)
	if err != nil {
		return "", 0, err
	}
	dst, err := canonicalPath(target)
	if err != nil {
		return "", 0, err
	}
	rel, err := filepath.Rel(root, dst)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", 0, fmt.Errorf("tarball target must be outside candidate inputs")
	}
	path, pin := s.approvalRegistry()
	trust, err := loadApprovalTrust(path, pin, dir, filepath.Dir(target))
	if err != nil {
		return "", 0, err
	}
	m, err := verifyCandidateWithTrust(dir, trust)
	if err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".tar-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(f.Name())
	err = writeV3Tar(dir, m, f)
	ce := f.Close()
	if err != nil {
		return "", 0, err
	}
	if ce != nil {
		return "", 0, ce
	}
	sum, size, err := hashFile(f.Name())
	if err != nil {
		return "", 0, err
	}
	if err := os.Rename(f.Name(), target); err != nil {
		return "", 0, err
	}
	return sum, size, nil
}
