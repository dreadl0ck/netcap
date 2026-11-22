package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
)

// Every legacy HTML figure carries its missing coverage qualifications, including
// ECharts image exports. It must not imply a complete wire-traffic measurement.
func chartCoverageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		writer := &coverageWriter{ResponseWriter: w, path: r.URL.Path, request: r, chart: isChartPresentationRequest(r)}
		next.ServeHTTP(writer, r)
		writer.finish()
	})
}

type coverageWriter struct {
	http.ResponseWriter
	path        string
	started     bool
	html        bool
	pending     []byte
	inserted    bool
	request     *http.Request
	nonce       string
	chart       bool
	errorStatus int
	diagnostic  bytes.Buffer
}

func (w *coverageWriter) WriteHeader(code int) {
	w.started = true
	if w.chart && code >= 400 && strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
		w.errorStatus = code
		return
	}
	w.html = code >= 200 && code < 300 && strings.Contains(w.Header().Get("Content-Type"), "text/html")
	if w.html {
		presentationHeaders(w, PresentationFromRequest(w.request))
		w.Header().Del("Content-Length")
		w.Header().Set("X-Netcap-Coverage", "retained-records; sampling=unreported; completeness=unreported")
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *coverageWriter) Write(p []byte) (int, error) {
	if w.errorStatus != 0 {
		return w.diagnostic.Write(p)
	}
	if !w.started {
		w.started = true
		w.html = strings.Contains(w.Header().Get("Content-Type"), "text/html")
		if w.html {
			presentationHeaders(w, PresentationFromRequest(w.request))
			w.Header().Del("Content-Length")
			w.Header().Set("X-Netcap-Coverage", "retained-records; sampling=unreported; completeness=unreported")
		}
	}
	if !w.html {
		return w.ResponseWriter.Write(p)
	}
	data := append(w.pending, p...)
	w.pending = nil
	if w.nonce == "" {
		if match := chartScriptNonce.FindSubmatch(data); len(match) == 2 {
			w.nonce = string(match[1])
		}
	}
	if bytes.Contains(data, []byte(`data-netcap-coverage="v1"`)) {
		w.inserted = true
	}
	if !w.inserted {
		if index := bytes.Index(bytes.ToLower(data), []byte("</body>")); index >= 0 {
			data = bytes.Join([][]byte{data[:index], w.annotation(), data[index:]}, nil)
			w.inserted = true
		}
	}
	// Keep only a small suffix so a closing tag split across writes is recognized.
	if !w.inserted && len(data) > 64 {
		w.pending = append([]byte(nil), data[len(data)-64:]...)
		data = data[:len(data)-64]
	} else if !w.inserted {
		w.pending = data
		return len(p), nil
	}
	_, err := w.ResponseWriter.Write(data)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (w *coverageWriter) annotation() []byte {
	message := "Retained audit summaries · sampling/completeness unreported · derived rates, not wire-volume measurements"
	if strings.Contains(w.path, "sankey") || strings.Contains(w.path, "protocol-hierarchy") {
		message = "Schematic protocol relationships · synthesized links, not observed packet parentage · audit counts, not wire volume"
	}
	var coverage RenderedChartCoverage
	if encoded := w.Header().Get("X-Netcap-Chart-Coverage"); encoded != "" && json.Unmarshal([]byte(encoded), &coverage) == nil {
		message = coverage.Text()
	}
	if w.nonce != "" {
		var measured *RenderedChartCoverage
		if w.Header().Get("X-Netcap-Chart-Coverage") != "" {
			measured = &coverage
		}
		texts := chartCoverageTexts(measured, strings.Contains(w.path, "sankey") || strings.Contains(w.path, "protocol-hierarchy"))
		p := PresentationFromRequest(w.request)
		return []byte(`<aside role="note" data-netcap-coverage="v1" style="font:11px sans-serif;padding:6px;white-space:pre-wrap">` + html.EscapeString(texts[p.Locale]) + `</aside><script nonce="` + w.nonce + `">window.netcapSetCoverage&&window.netcapSetCoverage(` + presentationJSON(texts) + `);</script>`)
	}
	fragment := `<aside role="note" data-netcap-coverage="v1" style="font:11px sans-serif;padding:6px;color:#888;white-space:pre-wrap">` + html.EscapeString(message) + `</aside>`
	// Insert a chart graphic as well: getDataURL (PNG/SVG) excludes HTML chrome.
	fragment += `<script>(function(){function annotate(){if(!window.echarts)return;document.querySelectorAll('[_echarts_instance_]').forEach(function(el){var c=echarts.getInstanceByDom(el);if(c)c.setOption({graphic:[{id:'netcap-coverage',type:'text',left:8,bottom:2,silent:true,style:{text:` + fmt.Sprintf("%q", strings.ReplaceAll(message, " · ", "\n")) + `,fill:'#888',fontSize:9,lineHeight:11}}]});});}window.addEventListener('load',annotate,{once:true});document.addEventListener('DOMContentLoaded',annotate,{once:true});})();</script>`
	return []byte(fragment)
}

var chartScriptNonce = regexp.MustCompile(`<script nonce="([A-Za-z0-9+/]+)"`)

func (w *coverageWriter) finish() {
	if w.errorStatus != 0 {
		diagnostic := strings.TrimSuffix(w.diagnostic.String(), "\n")
		if w.Header().Get("X-Netcap-Error-Code") != "" {
			http.Error(w.ResponseWriter, diagnostic, w.errorStatus)
		} else {
			chartHTTPError(w.ResponseWriter, w.request, diagnostic, w.errorStatus)
		}
		return
	}
	if !w.html {
		return
	}
	if len(w.pending) > 0 {
		_, _ = w.ResponseWriter.Write(w.pending)
	}
	if !w.inserted {
		_, _ = w.ResponseWriter.Write(w.annotation())
	}
}
func (w *coverageWriter) Flush() {
	if w.errorStatus != 0 {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *coverageWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func chartPresentationResponse(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func()) {
	writer := &coverageWriter{ResponseWriter: w, path: r.URL.Path, request: r, chart: true}
	return writer, writer.finish
}

func isChartPresentationRequest(r *http.Request) bool {
	if r.URL.Path == "/api/chart/data" || r.URL.Path == "/api/charts/data" || strings.HasPrefix(r.URL.Path, "/api/visualize/") {
		return true
	}
	if r.URL.Path == "/api/behavior/topology" {
		return r.URL.Query().Get("format") == "html"
	}
	return chartPresentationRoutes[r.URL.Path]
}

var chartPresentationRoutes = func() map[string]bool {
	routes := map[string]bool{}
	groups := map[string][]string{
		"hosts":           {"top-talkers", "traffic-distribution", "applications", "protocols"},
		"devices":         {"mac-vendors", "hardware", "operating-systems", "applications", "traffic-distribution"},
		"connections":     {"top-by-traffic", "protocols", "applications", "duration"},
		"http":            {"top-hosts", "status-codes", "methods", "content-types"},
		"certificates":    {"top-issuers", "status-distribution", "key-algorithms", "expiration-timeline"},
		"secrets":         {"by-service", "timeline", "usernames", "flows"},
		"services":        {"top-by-traffic", "protocols", "top-ports", "top-products"},
		"domains":         {"top-by-queries", "tlds", "record-types", "subdomain-distribution"},
		"fingerprints":    {"type-distribution", "top-ja4", "top-ja4ssh", "hosts-per-fingerprint"},
		"software":        {"top-products", "vendors", "operating-systems", "versions"},
		"vulnerabilities": {"severity", "top-vulnerable-software", "access-vectors", "exploit-types", "top-affected-hosts"},
	}
	for group, names := range groups {
		for _, name := range names {
			routes["/api/"+group+"/"+name] = true
		}
	}
	return routes
}()
