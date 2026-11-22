//go:build !appstore

package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBundledFontBrowser(t *testing.T) {
	if os.Getenv("NETCAP_TEST_FONT_BROWSER") != "1" {
		t.Skip("manual browser check: NETCAP_TEST_FONT_BROWSER=1")
	}
	root, err := filepath.Abs("frontend/public")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "static/fonts/noto-sans-sc/index.css")); err != nil {
		t.Fatalf("run pnpm fonts first: %v", err)
	}
	base := `<html><head><script src="/static/echarts/echarts.min.js"></script></head><body><div id="font-chart" style="height:400px;width:700px"></div><script>var goecharts_font=echarts.init(document.getElementById('font-chart'));var option_font={animation:false,title:{text:'Top HTTP Hosts'},legend:{selected:{Requests:false}},dataZoom:[{type:'inside',start:12,end:88}],xAxis:{type:'category',data:['捕获样本']},yAxis:{name:'Requests'},series:[{type:'bar',name:'Requests',data:[5]}]};goecharts_font.setOption(option_font);</script></body></html>`
	document := finalizeChartHTML(presentChartHTML([]byte(base), chartPresentation{Presentation: Presentation{Theme: "dark", Locale: "zh-Hans"}}))
	bootstrap, err := os.ReadFile("frontend/src/fontStylesheet.ts")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	s := &Server{addr: server.Listener.Addr().String(), localAccessToken: "font-test-not-an-api-token", assetsPath: root}
	assets := s.handleStatic()
	fonts := s.localSecurityMiddleware(s.corsMiddleware(assets))
	runID := fmt.Sprintf("font-%d", time.Now().UnixNano())
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/__font_test":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"runId": runID})
		case r.URL.Path == "/chart":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(document)
		case r.URL.Path == "/font-bootstrap.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(bootstrap)
		case strings.HasPrefix(r.URL.Path, "/static/fonts/"):
			fonts.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/static/echarts/"):
			assets.ServeHTTP(w, r)
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><script type="module" src="/font-bootstrap.js"></script><p id="font-probe" style="font-family:'Noto Sans SC Variable';font-size:20px"></p>`)
		default:
			http.NotFound(w, r)
		}
	})
	server.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "frontend/scripts/check-fonts-browser.mjs", server.URL, runID)
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "PLAYWRIGHT_BROWSERS_PATH", "NETCAP_TEST_CHROME"} {
		if value, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+value)
		}
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline font browser check: %v\n%s", err, output)
	} else {
		t.Log(strings.TrimSpace(string(output)))
	}
}
