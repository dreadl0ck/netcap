package dbs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/vulndb"
)

func buildFixtureSQLite(t *testing.T, dir string) {
	t.Helper()
	build := t.TempDir()
	year := time.Now().Year()
	writeGz(t, filepath.Join(build, "nvdcve-2.0-"+strconv.Itoa(year)+".json.gz"), nvdFixture)
	if err := BuildVulnDB(build, dir, year, false); err != nil {
		t.Fatal(err)
	}
}

// All grants/reviews in these fixtures refer only to synthetic test data.
func approveFixtureDirectory(t *testing.T, dir string) (string, ReleaseManifest) {
	t.Helper()
	files, err := scanCandidate(dir)
	if err != nil {
		t.Fatal(err)
	}
	var evidence []SourceEvidence
	var reviews []ReviewedSource
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Source] {
			continue
		}
		seen[f.Source] = true
		grant := "Synthetic fixture grant: permission to use these test bytes in this hermetic test. No production data is licensed by this text."
		e := SourceEvidence{ID: f.Source, Origin: "urn:netcap:synthetic-test", Revision: "fixture-1", SHA256: digest([]byte(f.Source)), Transformation: "synthetic fixtures", GrantText: grant, GrantSHA256: digest([]byte(grant)), NoticeText: "Copyright: synthetic test fixture only", GrantOrigin: "urn:netcap:synthetic-test-grant", GrantRevision: "fixture-grant-1"}
		if f.Source == "nvd" {
			db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			meta, err := db.Meta()
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			e.SHA256 = meta["input_sha256"]
			if err := decodeJSON([]byte(meta["nvd_inputs"]), &e.NVDInputs); err != nil {
				t.Fatal(err)
			}
		} else if f.Source == "dbip" {
			sum, _, err := hashFile(filepath.Join(dir, "geoip-sources.json"))
			if err != nil {
				t.Fatal(err)
			}
			e.SHA256 = sum
		} else {
			e.SHA256 = f.SHA256
		}
		evidence = append(evidence, e)
		var outputs []ReleaseFile
		for _, out := range files {
			if out.Source == f.Source {
				outputs = append(outputs, out)
			}
		}
		reviews = append(reviews, ReviewedSource{e, outputs, "approved-for-publication", "test-reviewer", "synthetic-review-1", "2026-10-01T00:00:00Z"})
	}
	if err := WriteCandidate(dir, evidence); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reviews.json")
	if err := atomicJSON(path, reviews); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pin := digest(b)
	t.Setenv(ApprovalRegistryEnv, path)
	t.Setenv(ApprovalRegistryPinEnv, pin)
	return path, ReleaseManifest{Candidate: Candidate{V3Layout, VulnDBSchema, files, evidence}, Reviews: reviews, ApprovalRegistrySHA256: pin}
}

func reviewedFixture(t *testing.T) (string, string, ReleaseManifest) {
	t.Helper()
	dir := t.TempDir()
	buildFixtureSQLite(t, dir)
	path, m := approveFixtureDirectory(t, dir)
	return dir, path, m
}

func TestV3PolicyRequiresReviewedExactSnapshot(t *testing.T) {
	dir, reviews, m := reviewedFixture(t)
	if _, err := VerifyCandidate(dir, ""); err == nil {
		t.Fatal("absent reviews accepted")
	}
	if _, err := VerifyCandidate(dir, filepath.Join(dir, CandidateFile)); err == nil {
		t.Fatal("self authorization accepted")
	}
	for _, kind := range []string{"decision", "grant", "input-hash", "output", "reviewer", "transformation", "scope"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := json.Marshal(m.Reviews)
			var changed []ReviewedSource
			json.Unmarshal(b, &changed)
			r := &changed[0]
			switch kind {
			case "decision":
				r.Decision = "candidate"
			case "grant":
				r.Evidence.GrantText += "changed"
			case "input-hash":
				r.Evidence.SHA256 = digest([]byte("different snapshot"))
			case "output":
				r.Outputs[0].SHA256 = digest([]byte("different output"))
			case "reviewer":
				r.Reviewer = ""
			case "transformation":
				r.Evidence.Transformation = "unknown transform"
			case "scope":
				r.Outputs = nil
			}
			path := filepath.Join(t.TempDir(), "changed.json")
			atomicJSON(path, changed)
			if _, err := VerifyCandidate(dir, path); err == nil {
				t.Fatal("changed review accepted")
			}
		})
	}
	if _, err := VerifyCandidate(dir, reviews); err != nil {
		t.Fatal(err)
	}
}

func TestV3AllProducersRejectContamination(t *testing.T) {
	for _, name := range []string{"cmsdb.json", "dhcp-fingerprints.json", "macaddress.io-db.json", "files_exploits.csv", "exploitdb/poc", "nested/cmsdb.json", "nvd.bleve/store", "exploit-db.bleve/index", "unknown.json", "nmap-service-probes", "GeoLite2-ASN.mmdb"} {
		t.Run(name, func(t *testing.T) {
			dir, reviews, _ := reviewedFixture(t)
			t.Setenv("NC_DBS_APPROVALS", reviews)
			p := filepath.Join(dir, name)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte("unapproved"), 0o644)
			var out bytes.Buffer
			if err := makeTarball(dir, "dbs", &out); err == nil {
				t.Fatal("generator accepted contamination")
			}
			if _, _, err := new(DBServer).createTarball(dir, filepath.Join(t.TempDir(), "out.tar.gz")); err == nil {
				t.Fatal("nightly accepted contamination")
			}
			if _, err := PackV3(dir, t.TempDir(), reviews); err == nil {
				t.Fatal("manual accepted contamination")
			}
			b, _ := os.ReadFile(p)
			if string(b) != "unapproved" {
				t.Fatal("input modified")
			}
		})
	}
	dir, reviews, _ := reviewedFixture(t)
	if err := os.Symlink(filepath.Join(dir, "netcap.sqlite"), filepath.Join(dir, "hasshdb.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCandidate(dir, reviews); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestV3OutputAliasCannotModifyCandidate(t *testing.T) {
	dir, reviews, _ := reviewedFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)
	if _, err := PackV3(dir, alias, reviews); err == nil {
		t.Fatal("output alias accepted")
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) {
		t.Fatal("packing modified candidate inputs")
	}
}

func TestV3AtomicPublicationAndServeOnly(t *testing.T) {
	dir, reviews, _ := reviewedFixture(t)
	out := t.TempDir()
	meta, err := PackV3(dir, out, reviews)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(out, "latest.json"))
	immutable, _ := os.ReadFile(filepath.Join(out, meta.Version+".json"))
	again, err := PackV3(dir, out, reviews)
	if err != nil || *again != *meta {
		t.Fatal("repack changed identity", again, err)
	}
	if after, _ := os.ReadFile(filepath.Join(out, meta.Version+".json")); !bytes.Equal(immutable, after) {
		t.Fatal("immutable metadata overwritten")
	}
	os.WriteFile(filepath.Join(dir, "netcap.sqlite"), []byte("tampered"), 0o644)
	if _, err := PackV3(dir, out, reviews); err == nil {
		t.Fatal("tampered source published")
	}
	if after, _ := os.ReadFile(filepath.Join(out, "latest.json")); !bytes.Equal(before, after) {
		t.Fatal("failed build replaced latest")
	}
	s := newTestServer(t)
	s.dbsDir = out
	if err := s.initialize(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/dbs/latest", "/dbs/list", "/dbs/v2/latest", "/dbs/v2/latest.tar.gz"} {
		r := httptest.NewRecorder()
		s.Handler().ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 410 {
			t.Fatalf("%s: %d", path, r.Code)
		}
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	got, err := fetchMetadata(server.URL)
	if err != nil || *got != *meta {
		t.Fatal(got, err)
	}
	resp, err := server.Client().Get(server.URL + "/dbs/v3/" + meta.Tarball)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if digest(body) != meta.SHA256 {
		t.Fatal("served body mismatch")
	}
	os.WriteFile(filepath.Join(out, meta.Tarball), []byte("corrupt cache"), 0o644)
	newServer := newTestServer(t)
	newServer.dbsDir = out
	if err := newServer.initialize(); err == nil || newServer.ready.Load() {
		t.Fatal("corrupt cached archive served")
	}
}

func TestV3ArchiveRejectsTraversalLinksDuplicatesAndUnknown(t *testing.T) {
	_, _, reviewed := reviewedFixture(t)
	for _, name := range []string{"../escape", "/absolute", "..", "dbs/netcap.sqlite", "unknown", "netcap.sqlite", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			typeFlag := byte(tar.TypeReg)
			headerName := name
			if name == "duplicate" {
				headerName = "netcap.sqlite"
			}
			if name == "netcap.sqlite" {
				typeFlag = tar.TypeSymlink
			}
			if err := tw.WriteHeader(&tar.Header{Name: headerName, Typeflag: typeFlag, Linkname: "outside", Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
			if name == "duplicate" {
				if err := tw.WriteHeader(&tar.Header{Name: headerName, Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
					t.Fatal(err)
				}
			}
			tw.Close()
			gz.Close()
			sum := digest(buf.Bytes())
			meta := &DBMetadata{Version: sum, SHA256: sum, Size: int64(buf.Len()), Tarball: sum + ".tar.gz", Layout: V3Layout, VulnDBSchema: 1, ManifestSHA256: sum, NVDStartYear: time.Now().Year(), NVDEndYear: time.Now().Year(), ApprovalRegistrySHA256: reviewed.ApprovalRegistrySHA256}
			path := filepath.Join(t.TempDir(), "attack.gz")
			os.WriteFile(path, buf.Bytes(), 0o644)
			if err := VerifyV3Archive(path, meta); err == nil {
				t.Fatal("hostile archive accepted")
			}
		})
	}
}

func TestV3DownloadTransactionalAndNoAmbientData(t *testing.T) {
	dir, reviews, _ := reviewedFixture(t)
	out := t.TempDir()
	meta, err := PackV3(dir, out, reviews)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.dbsDir = out
	if err := s.initialize(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	oldRoot, oldDBs := resolvers.ConfigRootPath, resolvers.DataBaseFolderPath
	t.Cleanup(func() { resolvers.ConfigRootPath = oldRoot; resolvers.DataBaseFolderPath = oldDBs })
	resolvers.ConfigRootPath = t.TempDir()
	resolvers.DataBaseFolderPath = filepath.Join(resolvers.ConfigRootPath, "dbs")
	os.Mkdir(resolvers.DataBaseFolderPath, 0o755)
	os.WriteFile(filepath.Join(resolvers.DataBaseFolderPath, "nmap-service-probes"), []byte("ambient"), 0o644)
	if err := DownloadDBs(server.URL, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(resolvers.DataBaseFolderPath, "nmap-service-probes")); !os.IsNotExist(err) {
		t.Fatal("ambient data remained active")
	}
	backups, _ := filepath.Glob(filepath.Join(resolvers.ConfigRootPath, ".netcap-switch-*", "previous-dbs", "nmap-service-probes"))
	if len(backups) != 1 {
		t.Fatal("previous user installation not preserved")
	}
	link, _ := os.Readlink(resolvers.DataBaseFolderPath)
	if err := DownloadDBs(server.URL, false); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Readlink(resolvers.DataBaseFolderPath); after != link {
		t.Fatal("verified current install unnecessarily switched")
	}
	os.WriteFile(filepath.Join(out, meta.Tarball), []byte("broken response"), 0o644)
	if err := DownloadDBs(server.URL, true); err == nil {
		t.Fatal("broken transfer installed")
	}
	if after, _ := os.Readlink(resolvers.DataBaseFolderPath); after != link {
		t.Fatal("failed download replaced active release")
	}
	if err := verifyInstalled(resolvers.DataBaseFolderPath, meta); err != nil {
		t.Fatal(err)
	}
}

func TestV3MissingYearAndCorruptFeedPreserveDatabase(t *testing.T) {
	out := t.TempDir()
	buildFixtureSQLite(t, out)
	before, _ := os.ReadFile(filepath.Join(out, "netcap.sqlite"))
	build := t.TempDir()
	year := time.Now().Year()
	writeGz(t, filepath.Join(build, fmt.Sprintf("nvdcve-2.0-%d.json.gz", year)), nvdFixture)
	if err := BuildVulnDB(build, out, year-1, false); err == nil {
		t.Fatal("missing required year accepted")
	}
	writeGz(t, filepath.Join(build, fmt.Sprintf("nvdcve-2.0-%d.json.gz", year-1)), strings.TrimSuffix(nvdFixture, "}"))
	if err := BuildVulnDB(build, out, year-1, false); err == nil {
		t.Fatal("truncated feed accepted")
	}
	after, _ := os.ReadFile(filepath.Join(out, "netcap.sqlite"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed build replaced prior SQLite")
	}
}

func TestV3SQLiteRebuildReproducesReviewedBytes(t *testing.T) {
	build := t.TempDir()
	year := time.Now().Year()
	writeGz(t, filepath.Join(build, fmt.Sprintf("nvdcve-2.0-%d.json.gz", year)), nvdFixture)
	previous := ""
	for i := 0; i < 4; i++ {
		out := t.TempDir()
		if err := BuildVulnDB(build, out, year, false); err != nil {
			t.Fatal(err)
		}
		sum, _, err := hashFile(filepath.Join(out, "netcap.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		if previous != "" && previous != sum {
			t.Fatal("identical reviewed inputs produced different SQLite bytes")
		}
		previous = sum
	}
}

func TestPackWrapperNoDeploymentAndPropagatesFailure(t *testing.T) {
	cmd := exec.Command("bash", "../../zeus/scripts/pack-dbs.sh", "-d", t.TempDir(), "-a", "reviews.json", "--approvals-sha256", digest([]byte("synthetic wrapper fixture")))
	cmd.Env = append(os.Environ(), "NETCAP_BIN=/usr/bin/false")
	if body, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("wrapper swallowed pack failure")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("wrapper did not propagate binary exit 1: %s %v", body, err)
	}
	cmd = exec.Command("bash", "../../zeus/scripts/pack-dbs.sh", "-D", "true")
	if body, err := cmd.CombinedOutput(); err == nil || !bytes.Contains(body, []byte("Deployment is not supported")) {
		t.Fatal(string(body), err)
	}
}

type v3RoundTripFunc func(*http.Request) (*http.Response, error)

func (f v3RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestV3FreshAcquisitionIsUnapprovedAndRequiredNVDIsFatal(t *testing.T) {
	t.Setenv("NC_DBS_APPROVALS", "")
	t.Setenv("NC_DBS_SKIP_SOURCES", "")
	t.Setenv("NC_DBS_SOURCE_TIMEOUT", "30ms")
	month := time.Now().UTC().Format("2006-01")
	city, asn := dbipPayload(t, "city", month), dbipPayload(t, "asn", month)
	var nvd bytes.Buffer
	gz := gzip.NewWriter(&nvd)
	gz.Write([]byte(nvdFixture))
	gz.Close()
	failedNVD := true
	requests := map[string]int{}
	oldClient := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = oldClient })
	http.DefaultClient = &http.Client{Transport: v3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests[r.URL.String()]++
		body, status := []byte("synthetic static fixture"), 200
		switch {
		case strings.HasSuffix(r.URL.Path, "/hasshdb"):
			body = []byte("004238f88dc63904baf2d5cf128db12f SSH-2.0-fixture (100)\n")
		case strings.Contains(r.URL.Path, "nvdcve-"):
			body = nvd.Bytes()
			if failedNVD {
				status = 503
			}
		case strings.Contains(r.URL.Path, "dbip-city-"):
			body = city
		case strings.Contains(r.URL.Path, "dbip-asn-"):
			body = asn
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
	root := t.TempDir()
	if _, err := BuildCandidate(root, time.Now().Year()); err == nil || !strings.Contains(err.Error(), "required NVD year") {
		t.Fatal("failed year did not stop fresh build", err)
	}
	failedNVD = false
	dir, err := BuildCandidate(root, time.Now().Year())
	if err != nil {
		t.Fatal(err)
	}
	var c Candidate
	if err := readJSON(filepath.Join(dir, CandidateFile), &c); err != nil {
		t.Fatal(err)
	}
	for _, s := range c.Sources {
		if s.GrantText != "" || s.GrantSHA256 != "" {
			t.Fatal("generator invented rights approval")
		}
	}
	if _, err := PackV3(dir, t.TempDir(), ""); err == nil {
		t.Fatal("endpoint recovery bypassed rights review")
	}
	for url := range requests {
		for _, banned := range []string{"fingerbank", "dhcp-fingerprints", "cmsdb", "wappalyzer", "macaddress.io", "exploit-database"} {
			if strings.Contains(url, banned) {
				t.Fatalf("uncleared source acquired: %s", url)
			}
		}
	}
}

func TestV3NightlyFailureKeepsReadyRevisionAndReportsError(t *testing.T) {
	dir, reviews, _ := reviewedFixture(t)
	out := t.TempDir()
	meta, err := PackV3(dir, out, reviews)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.dbsDir = out
	if err := s.initialize(); err != nil {
		t.Fatal(err)
	}
	s.nvdStartYear = time.Now().Year() + 1
	if err := s.rebuildDatabases(); err == nil {
		t.Fatal("invalid required-input build succeeded")
	}
	if !s.ready.Load() || s.currentDate != meta.Version {
		t.Fatal("failed rebuild displaced previous revision")
	}
	r := httptest.NewRecorder()
	s.handleHealth(r, httptest.NewRequest("GET", "/health", nil))
	var health map[string]any
	json.Unmarshal(r.Body.Bytes(), &health)
	if health["last_build_error"] == "" || health["status"] != "healthy" {
		t.Fatal(health)
	}
}
