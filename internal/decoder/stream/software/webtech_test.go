package software

import (
	"github.com/dreadl0ck/netcap/internal/webtech"
	"strings"
	"testing"
)

func TestWebtechStoreAdmissionIsBoundedAndVisible(t *testing.T) {
	webtechEngine()
	old := Store.Items
	Store.Items = map[string]*AtomicSoftware{}
	webtechRuntime.Lock()
	claims := webtechRuntime.claims
	webtechRuntime.claims = 4096
	before := webtechRuntime.states["software-record-limit"]
	webtechRuntime.Unlock()
	t.Cleanup(func() {
		Store.Items = old
		webtechRuntime.Lock()
		webtechRuntime.claims = claims
		webtechRuntime.states["software-record-limit"] = before
		webtechRuntime.Unlock()
	})
	report := ObserveWebtech(webtech.Observation{Method: "GET", Status: 200, ContentType: "text/html"}, strings.NewReader("<meta name=generator content='WordPress 6.8'>"), "", "origin.example", "synthetic-flow", "", 1)
	if len(report.Matches) != 1 || len(Store.Items) != 0 {
		t.Fatal("admission did not bound retained records")
	}
	_, counts := WebtechDiagnostics()
	if counts["software-record-limit"] != before+1 {
		t.Fatal("silent record drop")
	}
}

func TestWebtechOriginIsolationAndLowConfidence(t *testing.T) {
	old := Store.Items
	t.Cleanup(func() { Store.Items = old })
	Store.Items = map[string]*AtomicSoftware{}
	m := webtech.Result{ID: "netcap.webtech.wordpress.generator.v1", Product: "WordPress", Version: "6.8", Precision: "numeric"}
	for _, host := range []string{"a.example", "b.example"} {
		s := RenderWebtech(m, host, "synthetic-flow", "synthetic-cid", 1)
		EnhanceSoftwareRecord(s)
		if s.ObservedHost != "" || s.ConfidenceLevel != "low" || s.DetectionMethod != "webtech_advertisement" {
			t.Fatal(s)
		}
		WriteSoftware([]*AtomicSoftware{{Software: s}}, nil)
	}
	if len(Store.Items) != 2 {
		t.Fatal("origin claims collapsed", Store.Items)
	}
}
