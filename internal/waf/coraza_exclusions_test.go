//go:build coraza

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCRSArgumentExceptionKeepsRouteMethodAndOtherTargetsProtected(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	c.CRSTargetExclusions = []CRSTargetExclusion{{Path: "/api/account", Method: "POST", Argument: "password", RuleID: 942100}}
	f := firewall(t, c, compiled(t, "enforce", "request", `Body contains "native-forbidden"`))
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
			f.ServeHTTP(w, r)
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
