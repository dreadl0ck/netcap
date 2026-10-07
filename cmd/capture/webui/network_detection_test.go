package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestNetworkDetectionCoverageAndEvidenceAPI(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	s.baseOutDir = s.outDir
	request := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleNetworkDetection(w, httptest.NewRequest(method, target, nil))
		return w
	}
	if w := request("GET", "/api/network-detection"); w.Code != http.StatusNotFound {
		t.Fatalf("missing coverage reported as %d", w.Code)
	}
	if err := os.WriteFile(filepath.Join(s.outDir, NetworkDetectionSnapshotName), []byte(`{"schema":1,"events":15,"alerts":0,"overflow":0,"late":0,"streamGaps":0,"keys":1,"flows":0,"indicators":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request("GET", "/api/network-detection"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"events":15`) || !strings.Contains(w.Body.String(), `"active":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/api/network-detection?inputFile=unknown"); w.Code != http.StatusNotFound {
		t.Fatal("unknown selector fell back")
	}
	if w := request("POST", "/api/network-detection"); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("unexpected write")
	}
	alert := &types.Alert{Timestamp: 1800000000000000000, RuleName: "dns.tunnel", RecordType: "NetworkDetection", SrcIP: "192.0.2.1", DstIP: "192.0.2.53", SrcPort: "40000", DstPort: "53", Domain: "tunnel.example", MatchedRecord: `{"schema":1,"observed":10}`}
	a := alertResponse(alert)
	if a.SrcPort != "40000" || a.Domain != "tunnel.example" || a.Timestamp != 1800000000000 {
		t.Fatal("API lost analyst context")
	}
	alert.MatchedRecord = `{"schema":1,"observed":11}`
	if a.AlertID == alertResponse(alert).AlertID {
		t.Fatal("different immutable evidence reused alert identity")
	}
}
