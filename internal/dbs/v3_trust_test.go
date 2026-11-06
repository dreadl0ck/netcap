package dbs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
)

func forgeArchive(t *testing.T, dir, out string, m ReleaseManifest) *DBMetadata {
	t.Helper()
	var body bytes.Buffer
	if err := writeV3Tar(dir, m, &body); err != nil {
		t.Fatal(err)
	}
	mb, _ := json.Marshal(m)
	sum := digest(body.Bytes())
	meta := &DBMetadata{Layout: V3Layout, VulnDBSchema: VulnDBSchema, Version: sum, SHA256: sum, Tarball: sum + ".tar.gz", Size: int64(body.Len()), ManifestSHA256: digest(mb), ApprovalRegistrySHA256: m.ApprovalRegistrySHA256, NVDStartYear: time.Now().Year(), NVDEndYear: time.Now().Year(), CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := os.WriteFile(filepath.Join(out, meta.Tarball), body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(out, meta.Version+".json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(out, "latest.json"), meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestV3EmbeddedReviewsCannotAuthorizeServerOrInstallation(t *testing.T) {
	dir, _, legitimate := reviewedFixture(t)
	forged := legitimate
	// Deep copy before changing claims: the operator file remains untouched.
	b, _ := json.Marshal(legitimate)
	json.Unmarshal(b, &forged)
	uncleared := []byte(`{"uncleared":"copied signature payload"}`)
	os.WriteFile(filepath.Join(dir, "hasshdb.json"), uncleared, 0o644)
	file := ReleaseFile{Path: "hasshdb.json", Source: "hassh", SHA256: digest(uncleared), Size: int64(len(uncleared))}
	claims := SourceEvidence{ID: "hassh", Origin: "urn:forged-origin", Revision: "forged-revision", SHA256: file.SHA256, Transformation: "byte-for-byte", GrantText: "Attacker's fabricated permission statement; this test text grants no real rights.", NoticeText: "Fabricated test notice", GrantOrigin: "urn:forged-license", GrantRevision: "forged-license-revision"}
	claims.GrantSHA256 = digest([]byte(claims.GrantText))
	forged.Files = append(forged.Files, file)
	forged.Sources = append(forged.Sources, claims)
	forged.Reviews = append(forged.Reviews, ReviewedSource{Evidence: claims, Outputs: []ReleaseFile{file}, Decision: "approved-for-publication", Reviewer: "attacker-self-appointed-reviewer", ReviewID: "forged-approval", ReviewedAt: "2026-10-01T00:00:00Z"})
	if err := validateManifest(forged); err != nil {
		t.Fatal("forgery must pass structural checks to exercise the independent trust gate", err)
	}
	atomicJSON(filepath.Join(dir, CandidateFile), forged.Candidate)
	if _, err := VerifyCandidate(dir, os.Getenv(ApprovalRegistryEnv)); err == nil {
		t.Fatal("candidate authorized its new payload with fabricated source evidence")
	}
	out := t.TempDir()
	meta := forgeArchive(t, dir, out, forged)
	if err := VerifyV3Archive(filepath.Join(out, meta.Tarball), meta); err == nil || !strings.Contains(err.Error(), "pinned operator registry") {
		t.Fatalf("forged embedded review accepted: %v", err)
	}
	s := newTestServer(t)
	s.dbsDir = out
	if err := s.initialize(); err == nil || s.ready.Load() {
		t.Fatal("startup trusted archive self-claims", err)
	}
	if _, err := os.Stat(filepath.Join(out, meta.Tarball)); err != nil {
		t.Fatal("startup deleted evidence", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dbs/v3/latest" {
			json.NewEncoder(w).Encode(meta)
			return
		}
		http.ServeFile(w, r, filepath.Join(out, meta.Tarball))
	}))
	defer server.Close()
	old := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = filepath.Join(t.TempDir(), "dbs")
	t.Cleanup(func() { resolvers.DataBaseFolderPath = old })
	os.Mkdir(resolvers.DataBaseFolderPath, 0o755)
	os.WriteFile(filepath.Join(resolvers.DataBaseFolderPath, "previous"), []byte("keep"), 0o644)
	if err := DownloadDBs(server.URL, true); err == nil {
		t.Fatal("client installed self-authorized manifest")
	}
	if b, _ := os.ReadFile(filepath.Join(resolvers.DataBaseFolderPath, "previous")); string(b) != "keep" {
		t.Fatal("rejected release altered previous install")
	}
	// Forging local metadata and a marker must not bypass the same trust gate.
	local := t.TempDir()
	mb, _ := json.Marshal(forged)
	os.WriteFile(filepath.Join(local, ManifestFile), mb, 0o644)
	atomicJSON(filepath.Join(local, ".release.json"), meta)
	if _, err := ManagedReleaseMetadata(local); err == nil {
		t.Fatal("local forged marker bypassed trust")
	}
}

func TestV3RegistryMustBeExternalAndIndependentlyPinned(t *testing.T) {
	dir, path, _ := reviewedFixture(t)
	meta, err := PackV3(dir, t.TempDir(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = meta
	pin := os.Getenv(ApprovalRegistryPinEnv)
	t.Setenv(ApprovalRegistryPinEnv, "")
	if _, err := VerifyCandidate(dir, path); err == nil {
		t.Fatal("unpinned operator records accepted")
	}
	t.Setenv(ApprovalRegistryPinEnv, pin)
	b, _ := os.ReadFile(path)
	inside := filepath.Join(dir, "operator-records.json")
	os.WriteFile(inside, b, 0o644)
	if _, err := loadApprovalTrust(inside, pin, dir); err == nil {
		t.Fatal("candidate-contained registry accepted")
	}
	alias := filepath.Join(t.TempDir(), "reviews.json")
	os.Symlink(path, alias)
	if _, err := loadApprovalTrust(alias, pin, dir); err == nil {
		t.Fatal("symlink registry accepted")
	}
	os.WriteFile(path, append(b, ' '), 0o644)
	if _, err := loadApprovalTrust(path, pin, dir); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatal("registry replacement bypassed pin", err)
	}
}

func TestV3RegistryRejectsAmbiguousDuplicateFields(t *testing.T) {
	dir, path, _ := reviewedFixture(t)
	b, _ := os.ReadFile(path)
	changed := bytes.Replace(b, []byte(`"decision": "approved-for-publication"`), []byte(`"decision": "candidate", "decision": "approved-for-publication"`), 1)
	if bytes.Equal(changed, b) {
		t.Fatal("fixture mutation did not change the registry")
	}
	os.WriteFile(path, changed, 0o644)
	if _, err := loadApprovalTrust(path, digest(changed), dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("ambiguous pinned review accepted", err)
	}
}

func TestV3NVDManifestCannotForgeYearCoverage(t *testing.T) {
	dir, _, m := reviewedFixture(t)
	e := &m.Sources[0]
	input := e.NVDInputs[0]
	previous := input
	previous.Year--
	previous.URL = nvdInputURL(previous.Year)
	e.NVDInputs = []NVDInput{previous, input}
	e.SHA256 = nvdInputDigest(e.NVDInputs)
	m.Reviews[0].Evidence = *e
	// Even explicitly pinned bad coverage claims cannot change what SQLite
	// actually records from frozen inputs.
	if err := atomicJSON(filepath.Join(dir, CandidateFile), m.Candidate); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bad-coverage.json")
	atomicJSON(path, m.Reviews)
	b, _ := os.ReadFile(path)
	t.Setenv(ApprovalRegistryPinEnv, digest(b))
	if _, err := VerifyCandidate(dir, path); err == nil || !strings.Contains(err.Error(), "snapshot inventory mismatch") {
		t.Fatalf("forged year coverage accepted: %v", err)
	}
	e.NVDInputs = []NVDInput{previous, input, input}
	if err := validateNVDInputs(e.NVDInputs); err == nil {
		t.Fatal("duplicate year accepted")
	}
	e.NVDInputs = []NVDInput{previous, input}
	e.NVDInputs[1].Year++
	if err := validateNVDInputs(e.NVDInputs); err == nil {
		t.Fatal("missing year accepted")
	}
}

func TestV3ReviewedOptionalServiceSignaturesAndFullGrants(t *testing.T) {
	dir, _, _ := reviewedFixture(t)
	body, _ := json.Marshal(servicesignatures.Builtin().Catalogue())
	os.WriteFile(filepath.Join(dir, servicesignatures.FileName), body, 0o644)
	path, m := approveFixtureDirectory(t, dir)
	for i := range m.Sources {
		if m.Sources[i].ID != "netcap-service-signatures" {
			continue
		}
		grant := "Synthetic primary grant, complete test text.\n\nPermission to redistribute these synthetic test bytes.\n\nNO WARRANTY; full disclaimer retained verbatim.\n"
		m.Sources[i].GrantText = grant
		m.Sources[i].GrantSHA256 = digest([]byte(grant))
		for j := range m.Reviews {
			if m.Reviews[j].Evidence.ID == m.Sources[i].ID {
				m.Reviews[j].Evidence = m.Sources[i]
			}
		}
	}
	atomicJSON(filepath.Join(dir, CandidateFile), m.Candidate)
	atomicJSON(path, m.Reviews)
	b, _ := os.ReadFile(path)
	pin := digest(b)
	t.Setenv(ApprovalRegistryPinEnv, pin)
	meta, err := PackV3(dir, t.TempDir(), path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ApprovalRegistrySHA256 != pin {
		t.Fatal("publication lost the operator trust identity")
	}
	notices := releaseNotices(m)
	for _, s := range m.Sources {
		if !bytes.Contains(notices, []byte(s.GrantText)) || !bytes.Contains(notices, []byte(s.NoticeText)) {
			t.Fatal("primary terms or notice truncated")
		}
	}
	if _, err := loadApprovalTrust(path, digest([]byte("download-provided-pin")), dir); err == nil {
		t.Fatal("untrusted replacement pin accepted")
	}
}

type mutatingResponse struct {
	*httptest.ResponseRecorder
	mutate func()
	once   sync.Once
}

func (w *mutatingResponse) Write(b []byte) (int, error) {
	w.once.Do(w.mutate)
	return w.ResponseRecorder.Write(b)
}

func TestV3ServeUsesFinalVerifiedSnapshotAcrossCacheMutation(t *testing.T) {
	dir, path, _ := reviewedFixture(t)
	out := t.TempDir()
	meta, err := PackV3(dir, out, path)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(out, meta.Tarball)
	w := &mutatingResponse{ResponseRecorder: httptest.NewRecorder(), mutate: func() { os.WriteFile(archive, []byte("unapproved replacement"), 0o644) }}
	serveVerifiedObject(w, httptest.NewRequest("GET", "/dbs/v3/"+meta.Tarball, nil), archive, *meta)
	if w.Code != 200 || digest(w.Body.Bytes()) != meta.SHA256 {
		t.Fatal("served bytes changed after preflight verification")
	}
	r := httptest.NewRecorder()
	serveVerifiedObject(r, httptest.NewRequest("GET", "/", nil), archive, *meta)
	if r.Code != 503 {
		t.Fatal("subsequent changed object was served")
	}
}

func TestV3ConcurrentMetadataPointerAndRetainedDigestObjects(t *testing.T) {
	dir1, _, m1 := reviewedFixture(t)
	dir2, _, _ := reviewedFixture(t)
	os.WriteFile(filepath.Join(dir2, "hasshdb.json"), []byte(`{"fixture":"different reviewed profile"}`), 0o644)
	_, m2 := approveFixtureDirectory(t, dir2)
	reviews := append([]ReviewedSource(nil), m1.Reviews...)
	for _, r := range m2.Reviews {
		if r.Evidence.ID != "nvd" {
			reviews = append(reviews, r)
		}
	}
	registry := filepath.Join(t.TempDir(), "union.json")
	atomicJSON(registry, reviews)
	b, _ := os.ReadFile(registry)
	pin := digest(b)
	t.Setenv(ApprovalRegistryEnv, registry)
	t.Setenv(ApprovalRegistryPinEnv, pin)
	out := t.TempDir()
	a, err := PackV3(dir1, out, registry)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(out, a.Tarball))
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for _, dir := range []string{dir1, dir2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				if _, err := PackV3(dir, out, registry); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			var meta DBMetadata
			if err := readJSON(filepath.Join(out, "latest.json"), &meta); err != nil {
				errs <- err
				return
			}
			if err := VerifyV3Archive(filepath.Join(out, meta.Tarball), &meta); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(out, a.Tarball)); !bytes.Equal(before, after) {
		t.Fatal("old immutable object was replaced")
	}
	s := newTestServer(t)
	s.dbsDir = out
	if err := s.initialize(); err != nil {
		t.Fatal(err)
	}
	if len(s.validated) != 2 {
		t.Fatalf("retained revisions=%d, want 2", len(s.validated))
	}
	for _, meta := range s.validated {
		r := httptest.NewRecorder()
		s.Handler().ServeHTTP(r, httptest.NewRequest("GET", "/dbs/v3/"+meta.Tarball, nil))
		if r.Code != 200 || digest(r.Body.Bytes()) != meta.SHA256 {
			t.Fatal("retained digest URL unavailable")
		}
	}
}

func TestV3FreezeDoesNotReopenChangedAcquisitionInput(t *testing.T) {
	build := t.TempDir()
	year := time.Now().Year()
	name := fmt.Sprintf("nvdcve-2.0-%d.json.gz", year)
	writeGz(t, filepath.Join(build, name), nvdFixture)
	frozen := filepath.Join(t.TempDir(), "frozen")
	inputs, err := freezeNVDInputs(build, frozen, year, year)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(build, name), []byte("changed acquisition path"), 0o644)
	f, err := openRegular(filepath.Join(frozen, name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if digest(b) != inputs[0].SHA256 || int64(len(b)) != inputs[0].Size {
		t.Fatal("frozen feed changed with its acquisition path")
	}
}

func TestV3ChangedNightlyBytesRemainUnapprovedAndKeepPriorRelease(t *testing.T) {
	dir, registry, approved := reviewedFixture(t)
	out := t.TempDir()
	meta, err := PackV3(dir, out, registry)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.dbsDir = out
	s.nvdStartYear = time.Now().Year()
	if err := s.initialize(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(out, "latest.json"))
	registryBefore, _ := os.ReadFile(registry)
	t.Setenv("NC_DBS_SKIP_SOURCES", "hasshdb.json,regexes.yaml,service-names-port-numbers.csv")
	month := time.Now().UTC().Format("2006-01")
	city, asn := dbipPayload(t, "city", month), dbipPayload(t, "asn", month)
	feedPath := filepath.Join(t.TempDir(), "new-feed.gz")
	writeGz(t, feedPath, strings.ReplaceAll(nvdFixture, "Apache HTTP Server", "Changed Apache HTTP Server"))
	feed, _ := os.ReadFile(feedPath)
	oldClient := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = oldClient })
	http.DefaultClient = &http.Client{Transport: v3RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := feed
		if strings.Contains(r.URL.Path, "dbip-city-") {
			body = city
		} else if strings.Contains(r.URL.Path, "dbip-asn-") {
			body = asn
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
	if err := s.rebuildDatabases(); err == nil {
		t.Fatal("nightly granted itself permission for new bytes")
	}
	if !s.ready.Load() || s.currentDate != meta.Version || s.lastBuildError == "" {
		t.Fatal("nightly did not preserve the ready release and visible error")
	}
	if after, _ := os.ReadFile(filepath.Join(out, "latest.json")); !bytes.Equal(before, after) {
		t.Fatal("blocked nightly replaced metadata pointer")
	}
	if after, _ := os.ReadFile(registry); !bytes.Equal(registryBefore, after) {
		t.Fatal("nightly modified operator approvals")
	}
	paths, _ := filepath.Glob(filepath.Join(s.buildDir, "candidates", "candidate-*", "dbs", CandidateFile))
	if len(paths) != 1 {
		t.Fatal("missing reviewable blocked candidate", paths)
	}
	var candidate Candidate
	if err := readJSON(paths[0], &candidate); err != nil {
		t.Fatal(err)
	}
	for _, source := range candidate.Sources {
		if source.ID == "nvd" && (source.SHA256 == approved.Sources[0].SHA256 || source.GrantText != "") {
			t.Fatal("nightly inherited approval across an input change")
		}
	}
}

type mutatingWriter struct {
	io.Writer
	mutate func()
	once   sync.Once
}

func (w *mutatingWriter) Write(b []byte) (int, error) { w.once.Do(w.mutate); return w.Writer.Write(b) }

func TestV3TarWriterRejectsInputMutationAfterCandidateVerification(t *testing.T) {
	dir, path, _ := reviewedFixture(t)
	m, err := VerifyCandidate(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "netcap.sqlite")
	original, _ := os.ReadFile(file)
	var buf bytes.Buffer
	w := &mutatingWriter{Writer: &buf, mutate: func() { os.WriteFile(file, bytes.Repeat([]byte{'x'}, len(original)), 0o644) }}
	if err := writeV3Tar(dir, m, w); err == nil {
		t.Fatal("tar writer accepted changed bytes after policy validation")
	}
}
