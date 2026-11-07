//go:build coraza

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

func TestCRSProfileActualRulesAndExpiry(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	// 942100 is libinjection SQLi; a single score of 5 must cross threshold 5, not 6.
	for _, tc := range []struct {
		name, query string
		threshold   int
		expiry      time.Time
		parameter   string
		want        int
	}{
		{name: "default-deny", query: "q=1%27%20OR%20%271%27=%271", threshold: 5, want: 403},
		{name: "threshold", query: "q=1%27%20OR%20%271%27=%271", threshold: 100, want: 200},
		{name: "parameter-exclusion", query: "q=1%27%20OR%20%271%27=%271", threshold: 5, expiry: time.Now().Add(time.Hour), parameter: "q", want: 200},
		{name: "other-parameter", query: "other=1%27%20OR%20%271%27=%271", threshold: 5, expiry: time.Now().Add(time.Hour), parameter: "q", want: 403},
		{name: "expired", query: "q=1%27%20OR%20%271%27=%271", threshold: 5, expiry: time.Now().Add(-time.Minute), parameter: "q", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config(origin.URL)
			c.CorazaCRS = true
			c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: tc.threshold, OutboundThreshold: 4}
			if !tc.expiry.IsZero() {
				c.CRSProfile.Exclusions = []CRSExclusion{{RuleID: 942100, Parameter: tc.parameter, Owner: "operator", Reason: "search accepts SQL examples", ExpiresAt: tc.expiry}}
			}
			f := firewall(t, c, compiled(t, "enforce", "request", ""))
			r := httptest.NewRequest("GET", "http://route.example/?"+tc.query, nil)
			r.Header.Set("User-Agent", "test")
			r.Header.Set("Accept", "*/*")
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
}

func TestCRSParanoiaAndThresholdConfiguration(t *testing.T) {
	for pl := 1; pl <= 4; pl++ {
		c := config("http://unused.invalid")
		c.CorazaCRS = true
		c.CRSProfile = &CRSProfile{ParanoiaLevel: pl, InboundThreshold: 17, OutboundThreshold: 13}
		// Probe actual transaction variables after CRS initialization with real bundled rules.
		directives := corazaDirectives(c) + `SecRule TX:blocking_paranoia_level "!@eq ` + string(rune('0'+pl)) + `" "id:10000900,phase:2,deny,status:409,nolog"
SecRule TX:inbound_anomaly_score_threshold "!@eq 17" "id:10000901,phase:2,deny,status:409,nolog"
SecRule TX:outbound_anomaly_score_threshold "!@eq 13" "id:10000902,phase:2,deny,status:409,nolog"`
		w, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives))
		if err != nil {
			t.Fatal(err)
		}
		e := &corazaEngine{waf: w}
		r := httptest.NewRequest("GET", "http://route.example/", nil)
		r.Header.Set("Accept", "*/*")
		r.Header.Set("User-Agent", "test")
		tx, status, err := e.request(r, strings.NewReader(""), "192.0.2.1", false)
		if tx != nil {
			_ = tx.Close()
		}
		if err != nil || status != 0 {
			t.Fatalf("PL%d status=%d err=%v", pl, status, err)
		}
	}
}

func TestCRSUnknownExclusionsAndNativeControls(t *testing.T) {
	c := config("http://unused.invalid")
	c.CorazaCRS = true
	c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 100, OutboundThreshold: 100, Exclusions: []CRSExclusion{{RuleID: 942999, Owner: "operator", Reason: "test", ExpiresAt: time.Now().Add(time.Hour)}}}
	if f, err := New(c, compiled(t, "enforce", "request", "")); err == nil {
		f.Close()
		t.Fatal("unknown detector accepted")
	}
	c.CRSProfile.Exclusions[0].RuleID = 942100
	f := firewall(t, c, compiled(t, "enforce", "request", `Body contains "native-block"`))
	if w := call(f, "native-block"); w.Code != 403 {
		t.Fatal("CRS threshold overrode native deny", w.Code)
	}
	r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(`{"bad":`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("CRS tuning bypassed parser", w.Code)
	}
}

func TestCRSParanoiaRuleVectors(t *testing.T) {
	for _, vector := range []struct {
		query       string
		rule, level int
	}{
		{"q=1%27%20OR%20%271%27=%271", 942100, 1},
		{"q=0xdeadbeef", 942450, 2},
		{"q=a~b~c~d~e~f~g", 942431, 3},
		{"q=a~b~c", 942432, 4},
	} {
		for pl := 1; pl <= 4; pl++ {
			c := config("http://unused.invalid")
			c.CorazaCRS = true
			c.CRSProfile = &CRSProfile{ParanoiaLevel: pl, InboundThreshold: 100, OutboundThreshold: 100}
			engine, err := newInspectionEngine(c)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "http://route.example/?"+vector.query, nil)
			r.Header.Set("Accept", "*/*")
			r.Header.Set("User-Agent", "test")
			tx, status, err := engine.request(r, strings.NewReader(""), "192.0.2.1", false)
			if err != nil || status != 0 {
				t.Fatalf("PL%d: status=%d err=%v", pl, status, err)
			}
			found := false
			for _, m := range tx.(*corazaTransaction).MatchedRules() {
				if m.Rule().ID() == vector.rule {
					found = true
				}
			}
			_ = tx.Close()
			if found != (pl >= vector.level) {
				t.Fatalf("rule %d PL%d matched=%v", vector.rule, pl, found)
			}
		}
	}
}

func TestCRSRouteProfileIsolationAndOutboundThreshold(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/leak" {
			_, _ = w.Write([]byte("You have an error in your SQL syntax; near 'bad'"))
		}
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	c.InspectResponse = true
	c.Routes = []RouteConfig{routeFixture(t, origin.URL, "a", "a.example", "/", 0), routeFixture(t, origin.URL, "b", "b.example", "/", 0)}
	c.Routes[0].CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 100, Exclusions: []CRSExclusion{{RuleID: 942100, Parameter: "q", Owner: "operator", Reason: "SQL examples", ExpiresAt: time.Now().Add(time.Hour)}}}
	c.Routes[1].CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	for _, host := range []string{"a.example", "b.example"} {
		for _, p := range []string{"/?q=1%27%20OR%20%271%27=%271", "/leak"} {
			r := httptest.NewRequest("GET", "http://"+host+p, nil)
			r.Header.Set("Accept", "*/*")
			r.Header.Set("User-Agent", "test")
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			want := 200
			if host == "b.example" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("%s%s got %d want %d", host, p, w.Code, want)
			}
		}
	}
}

func TestCRSExclusionExpiresWithoutReload(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	expires := time.Now().Truncate(time.Second).Add(2 * time.Second)
	c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
		Exclusions: []CRSExclusion{{RuleID: 942100, Parameter: "q", Owner: "ops", Reason: "temporary", ExpiresAt: expires}}}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	check := func(want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "http://route.example/?q=1%27%20OR%20%271%27=%271", nil)
		r.Header.Set("Accept", "*/*")
		r.Header.Set("User-Agent", "test")
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("expiry status %d want %d", w.Code, want)
		}
	}
	check(200)
	time.Sleep(time.Until(expires) + 20*time.Millisecond)
	check(403)
}
