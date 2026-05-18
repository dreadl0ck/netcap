/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package dbs

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestFetchResource_ContextTimeout makes sure fetchResource respects the
// per-source wall-clock budget. The test stands up an httptest.Server that
// accepts the TCP connection but never writes a response, simulating the
// real-world blackhole we observed for ja4db.com. With the budget set low
// via the env override, the call must return within the budget plus a small
// scheduling margin instead of waiting on http.DefaultClient's default
// (effectively forever for a SYN-accepting hanging server).
func TestFetchResource_ContextTimeout(t *testing.T) {
	// Slow handler: hold the request open. We don't write anything; the
	// test relies on the context deadline tripping the client.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer ts.Close()

	t.Setenv("NC_DBS_SOURCE_TIMEOUT", "300ms")

	src := &datasource{url: ts.URL, name: "slow.bin"}
	out := filepath.Join(t.TempDir(), "slow.bin")

	start := time.Now()
	err := fetchResource(src, out)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from fetchResource against a hanging server")
	}
	// 300ms budget + per-attempt overhead + backoffs. The retry loop may
	// burn one or two attempts before the deadline fires, so allow some
	// slack but assert we're nowhere near the previous unbounded behaviour
	// (~95s in production).
	if elapsed > 5*time.Second {
		t.Errorf("fetchResource took %v, want bounded close to the 300ms budget", elapsed)
	}
}

// TestSourceTimeout_EnvOverride exercises the env parsing branches.
func TestSourceTimeout_EnvOverride(t *testing.T) {
	cases := []struct {
		name string
		v    string
		want time.Duration
	}{
		{"unset", "", defaultSourceTimeout},
		{"valid", "1500ms", 1500 * time.Millisecond},
		{"invalid", "not-a-duration", defaultSourceTimeout},
		{"zero", "0", defaultSourceTimeout},
		{"negative", "-5s", defaultSourceTimeout},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NC_DBS_SOURCE_TIMEOUT", c.v)
			if got := sourceTimeout(); got != c.want {
				t.Errorf("sourceTimeout: got %v, want %v", got, c.want)
			}
		})
	}
}

// TestFetchResource_NoURL is the trivial happy-path where a source has no
// URL (handled by a hook); fetchResource must return nil without any I/O.
func TestFetchResource_NoURL(t *testing.T) {
	src := &datasource{url: "", name: "from-hook"}
	if err := fetchResource(src, ""); err != nil {
		t.Errorf("expected nil error for empty-URL source, got: %v", err)
	}
}

// TestSkippedSourceNames covers the env parsing for NC_DBS_SKIP_SOURCES,
// including empty values, whitespace tolerance, and the "no env var set"
// path that should return nil so callers can avoid allocating a map.
func TestSkippedSourceNames(t *testing.T) {
	cases := []struct {
		name string
		v    string
		want []string // sorted list of expected keys; nil/empty means nil map
	}{
		{"unset", "", nil},
		{"empty", "   ", nil},
		{"single", "ja4db.json", []string{"ja4db.json"}},
		{"multi", "ja4db.json,hasshdb.json", []string{"hasshdb.json", "ja4db.json"}},
		{"whitespace", " ja4db.json , , hasshdb.json ", []string{"hasshdb.json", "ja4db.json"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NC_DBS_SKIP_SOURCES", c.v)
			got := skippedSourceNames()
			if len(c.want) == 0 {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("len: got %d (%v), want %d (%v)", len(got), got, len(c.want), c.want)
			}
			for _, k := range c.want {
				if _, ok := got[k]; !ok {
					t.Errorf("missing key %q in %v", k, got)
				}
			}
		})
	}
}

// TestActiveSources_FiltersByEnv verifies that activeSources removes the
// requested datasource from the default list. Uses a real source name from
// the package-level `sources` slice to keep the test honest.
func TestActiveSources_FiltersByEnv(t *testing.T) {
	// Sanity: ja4db.json is one of the defaults; this test is meaningless
	// otherwise. Loud failure is preferable to a silent skip.
	var foundJA4 bool
	for _, s := range sources {
		if s.name == "ja4db.json" {
			foundJA4 = true
			break
		}
	}
	if !foundJA4 {
		t.Fatal("default sources list no longer contains ja4db.json; update this test or the skip target")
	}

	t.Setenv("NC_DBS_SKIP_SOURCES", "ja4db.json")
	// Force a fresh log-once for this test scope so subsequent runs in the
	// same `go test` invocation aren't quieted. activeSources uses
	// sync.Once at package scope; we don't assert on the log line itself,
	// only on filtering.
	got := activeSources()
	if len(got) != len(sources)-1 {
		t.Fatalf("activeSources returned %d entries, want %d", len(got), len(sources)-1)
	}
	for _, s := range got {
		if s.name == "ja4db.json" {
			t.Errorf("activeSources did not skip ja4db.json")
		}
	}
}

// TestActiveSources_NoEnvReturnsAll exercises the fast path.
func TestActiveSources_NoEnvReturnsAll(t *testing.T) {
	t.Setenv("NC_DBS_SKIP_SOURCES", "")
	got := activeSources()
	if len(got) != len(sources) {
		t.Errorf("activeSources returned %d entries, want %d (no skip env)", len(got), len(sources))
	}
}

