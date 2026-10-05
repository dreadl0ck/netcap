package dbs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func dbipPayload(t *testing.T, kind, month string) []byte {
	t.Helper()
	dir := t.TempDir()
	date, _ := time.Parse("2006-01", month)
	dbType, record := "DBIP-City-Lite", testutil.City("NL", "Amsterdam")
	if kind == "asn" {
		dbType, record = "DBIP-ASN-Lite (compat=GeoLite2-ASN)", testutil.ASN(3333, "RIPE")
	}
	path := filepath.Join(dir, "fixture.mmdb")
	testutil.WriteMMDB(t, path, dbType, date, map[string]mmdbtype.Map{"193.0.6.0/24": record})
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(body)
	gz.Close()
	return compressed.Bytes()
}

func TestDBIPBundleArchiveValidation(t *testing.T) {
	for _, method := range []string{"generator", "server", "packer", "legacy-packer"} {
		t.Run(method, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "dbs")
			os.Mkdir(dir, 0o755)
			month := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			city, asn := dbipPayload(t, "city", "2026-10"), dbipPayload(t, "asn", "2026-10")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "city") {
					w.Write(city)
				} else {
					w.Write(asn)
				}
			}))
			defer server.Close()
			if err := ensureDBIP(dir, filepath.Join(root, "cache"), month, server.Client(), server.URL); err != nil {
				t.Fatal(err)
			}
			if method != "legacy-packer" {
				os.WriteFile(filepath.Join(dir, "netcap.sqlite"), []byte("fixture"), 0o644)
			}
			os.WriteFile(filepath.Join(dir, "GeoLite2-City.mmdb"), []byte("local data"), 0o644)
			build := func() ([]byte, error) {
				var buf bytes.Buffer
				switch method {
				case "generator":
					err := makeTarball(dir, "dbs", &buf)
					return buf.Bytes(), err
				case "server":
					path := filepath.Join(root, "server.tar.gz")
					_, _, err := new(DBServer).createTarball(dir, path)
					if err != nil {
						return nil, err
					}
					return os.ReadFile(path)
				default:
					cmd := exec.Command("bash", "../../zeus/scripts/pack-dbs.sh", "-d", dir, "-o", root, "-v", "2026-10-05", "-D", "false")
					if body, err := cmd.CombinedOutput(); err != nil {
						return nil, fmt.Errorf("%s: %w", body, err)
					}
					return os.ReadFile(filepath.Join(root, "2026-10-05.tar.gz"))
				}
			}
			body, err := build()
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			tr := tar.NewReader(gz)
			seen := map[string]bool{}
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				seen[filepath.Base(h.Name)] = true
			}
			for _, file := range []string{"dbip-city-lite.mmdb", "dbip-asn-lite.mmdb", "geoip-sources.json"} {
				if seen[file] != (method != "legacy-packer") {
					t.Fatalf("%s presence=%v", file, seen[file])
				}
			}
			if seen["GeoLite2-City.mmdb"] {
				t.Fatal("user data shipped")
			}
			if method != "legacy-packer" {
				os.WriteFile(filepath.Join(dir, "dbip-city-lite.mmdb"), []byte("tampered"), 0o644)
				if _, err := build(); err == nil {
					t.Fatal("packer accepted modified DB-IP")
				}
			}
		})
	}
}

func TestDBIPDownloadFallbackCacheAndValidation(t *testing.T) {
	month := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	payloads := map[string][]byte{}
	for _, m := range []string{"2026-09", "2026-10"} {
		for _, kind := range []string{"city", "asn"} {
			payloads[fmt.Sprintf("/dbip-%s-lite-%s.mmdb.gz", kind, m)] = dbipPayload(t, kind, m)
		}
	}
	mode, requests := "current", 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("User-Agent") != "netcap-dbs" {
			t.Error("missing user agent")
		}
		if mode == "outage" || (mode == "previous" && strings.Contains(r.URL.Path, "2026-10")) {
			http.NotFound(w, r)
			return
		}
		if mode == "corrupt" {
			w.Write([]byte("not gzip"))
			return
		}
		w.Write(payloads[r.URL.Path])
	}))
	defer server.Close()
	root := t.TempDir()
	dst := filepath.Join(root, "dbs")
	cache := filepath.Join(root, "cache")
	os.Mkdir(dst, 0o755)
	if err := ensureDBIP(dst, cache, month, server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	manifest, err := validateDBIP(dst)
	if err != nil || manifest[0].Release != "2026-10" {
		t.Fatal(manifest, err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d", requests)
	}
	mode = "outage"
	if err := ensureDBIP(dst, cache, month, server.Client(), server.URL); err != nil || requests != 2 {
		t.Fatal("current cache not reused", err, requests)
	}
	if err := ensureDBIP(dst, cache, month.AddDate(0, 1, 0), server.Client(), server.URL); err != nil {
		t.Fatal("valid old cache not retained", err)
	}
	if err := os.WriteFile(filepath.Join(cache, "dbip-city-lite.mmdb"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureDBIP(dst, cache, month, server.Client(), server.URL); err == nil {
		t.Fatal("accepted tampered cache during outage")
	}
	mode = "previous"
	if err := ensureDBIP(dst, cache, month, server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	manifest, err = validateDBIP(dst)
	if err != nil || manifest[0].Release != "2026-09" {
		t.Fatal(manifest, err)
	}
	mode = "corrupt"
	os.RemoveAll(cache)
	if err := ensureDBIP(dst, cache, month, server.Client(), server.URL); err == nil {
		t.Fatal("accepted corrupt download")
	}
	manifest, err = validateDBIP(dst)
	if err != nil || manifest[0].Release != "2026-09" {
		t.Fatal("corrupt download replaced previous files", manifest, err)
	}
}
