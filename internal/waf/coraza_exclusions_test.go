//go:build coraza

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
)

func TestCRSArgumentExceptionKeepsRouteMethodAndOtherTargetsProtected(t *testing.T) {
	crsExceptionBoundary(t, false)
}

func TestRoutedCRSProfileExactExceptionCompatibility(t *testing.T) {
	crsExceptionBoundary(t, true)
}

func crsExceptionBoundary(t *testing.T, routed bool) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	c.CRSTargetExclusions = []CRSTargetExclusion{{Path: "/api/account", Method: "POST", Argument: "password", RuleID: 942100}}
	if routed {
		c.CRSTargetExclusions = nil
		c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, Exclusions: []CRSExclusion{{Path: "/api/account", Method: "POST", Parameter: "password", RuleID: 942100, Owner: "fixture", Reason: "qualification password", ExpiresAt: time.Now().Add(time.Hour)}}}
	}
	_, _, handler := composedFirewall(t, c, compiled(t, "enforce", "request", `Body contains "native-forbidden"`), routed)
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"calibration-password", "POST", "/api/account", "password=Test%21%40%23%242026&confirm=yes", 200},
		{"held-out-password", "POST", "/api/account", "password=Other%21%40%23%242027&confirm=yes", 200},
		{"other-route", "POST", "/api/orders", "password=Test%21%40%23%242026", 403},
		{"other-method", "GET", "/api/account", "password=Test%21%40%23%242026", 403},
		{"other-field", "POST", "/api/account", "comment=Test%21%40%23%242026", 403},
		{"xss-same-field", "POST", "/api/account", "password=%3Cscript%3Ealert(1)%3C/script%3E", 403},
		{"native-still-enforced", "POST", "/api/account", "password=native-forbidden", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls.Load()
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Host = "fixture.test"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("User-Agent", "NetcapQualification/1.0")
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
			wantDelta := int64(0)
			if tc.want == 200 {
				wantDelta = 1
			}
			if calls.Load()-before != wantDelta {
				t.Fatal("origin reach disagrees with expected protection")
			}
		})
	}
}

func TestRoutedCRSExceptionCannotBypassAPIOrNative(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer origin.Close()
	c := apiConfig(t, config(origin.URL), map[string][]byte{"openapi.json": []byte(apiContract)}, apipolicy.Declaration{OpenAPI: "openapi.json"})
	c.CorazaCRS = true
	c.CRSProfile = &CRSProfile{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, Exclusions: []CRSExclusion{{Path: "/items", Method: "POST", Parameter: "json.text", RuleID: 942100, Owner: "fixture", Reason: "JSON qualification password", ExpiresAt: time.Now().Add(time.Hour)}}}
	_, _, handler := composedFirewall(t, c, compiled(t, "enforce", "request", `Body contains "native-forbidden"`), true)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"text":"Test!@#$2026","n":2}`, 200},
		{`{"text":"Test!@#$2026","n":99}`, 403},
		{`{"text":"native-forbidden","n":2}`, 403},
		{`{"text":"<script>alert(1)</script>","n":2}`, 403},
	} {
		before := calls.Load()
		r := httptest.NewRequest("POST", "http://fixture.test/items?limit=2", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Required", "yes")
		r.Header.Set("User-Agent", "NetcapQualification/1.0")
		r.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status || (tc.status != 200 && calls.Load() != before) {
			t.Fatalf("API/native/CRS composition: status=%d want=%d origin=%d body=%s", w.Code, tc.status, calls.Load()-before, w.Body.String())
		}
	}
}

func TestCRSTargetExceptionRejectsDirectiveInjectionAndBlanketScopes(t *testing.T) {
	valid := CRSTargetExclusion{Path: "/api/account", Method: "POST", Argument: "password", RuleID: 942100}
	for _, change := range []func(*CRSTargetExclusion){
		func(e *CRSTargetExclusion) { e.Path = "/api/*" },
		func(e *CRSTargetExclusion) { e.Path = "/api/\"\nSecRuleEngine Off" },
		func(e *CRSTargetExclusion) { e.Argument = "password;REQUEST_HEADERS" },
		func(e *CRSTargetExclusion) { e.Argument = "" },
		func(e *CRSTargetExclusion) { e.RuleID = 949110 },
		func(e *CRSTargetExclusion) { e.Method = "*" },
	} {
		e := valid
		change(&e)
		c := config("http://127.0.0.1:1")
		c.CorazaCRS = true
		c.CRSTargetExclusions = []CRSTargetExclusion{e}
		if ValidateConfig(c) == nil {
			t.Fatalf("accepted unsafe exception: %+v", e)
		}
	}
	c := config("http://127.0.0.1:1")
	c.CRSTargetExclusions = []CRSTargetExclusion{valid}
	if ValidateConfig(c) == nil {
		t.Fatal("exception without CRS accepted")
	}
	c.CorazaCRS = true
	c.CRSTargetExclusions = append(c.CRSTargetExclusions, valid)
	if ValidateConfig(c) == nil {
		t.Fatal("duplicate exception accepted")
	}
}
