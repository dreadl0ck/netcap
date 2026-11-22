package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

func TestPresentationRequestBoundsAndRegionalMatching(t *testing.T) {
	for _, tc := range []struct{ query, theme, locale string }{
		{"", "dark", "en"}, {"theme=light&locale=de-AT", "light", "de"},
		{"theme=dark&locale=nl-BE", "dark", "nl"}, {"locale=fr-CA", "dark", "fr"},
		{"locale=es-MX", "dark", "es"}, {"locale=zh-CN", "dark", "zh-Hans"},
		{"locale=zh-Hans-SG", "dark", "zh-Hans"}, {"locale=en-GB", "dark", "en"},
		{"theme=system&locale=it-IT", "dark", "en"}, {"theme=light&theme=dark&locale=de&locale=fr", "dark", "en"},
		{"theme=light&locale=%3Cscript%3E", "light", "en"}, {"locale=" + strings.Repeat("a", 1000), "dark", "en"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/chart/data?"+tc.query, nil)
			r.Header.Set("Accept-Language", "es")
			got := PresentationFromRequest(r)
			if got.Theme != tc.theme || got.Locale != tc.locale {
				t.Fatalf("got %+v, want %s/%s", got, tc.theme, tc.locale)
			}
		})
	}
}

func TestPresentationCatalogCompletenessAndFormatContracts(t *testing.T) {
	formats := regexp.MustCompile(`%[dst]`)
	parameters := regexp.MustCompile(`\{[A-Za-z]+\}`)
	for name, catalog := range map[string]map[string][6]string{"charts": chartPresentationCatalog, "metadata": metadataPresentationCatalog} {
		for english, row := range catalog {
			for i, value := range row {
				if value == "" || !strings.EqualFold(strings.Join(formats.FindAllString(english, -1), ","), strings.Join(formats.FindAllString(value, -1), ",")) {
					t.Errorf("%s %q locale %s has empty text or changed format parameters: %q", name, english, presentationLocales[i], value)
				}
				wantParams, gotParams := parameters.FindAllString(english, -1), parameters.FindAllString(value, -1)
				sort.Strings(wantParams)
				sort.Strings(gotParams)
				if strings.Join(wantParams, ",") != strings.Join(gotParams, ",") {
					t.Errorf("%q lost named parameters in %s: %q", english, presentationLocales[i], value)
				}
			}
			if row[0] != english {
				t.Errorf("English compatibility changed for %q", english)
			}
		}
	}
	check := func(english string) {
		t.Helper()
		if _, chart := chartPresentationCatalog[english]; !chart {
			if _, metadata := metadataPresentationCatalog[english]; !metadata {
				t.Errorf("missing six-language UI label: %q", english)
			}
		}
	}
	s := &Server{}
	for _, option := range s.getConfigOptions(nil) {
		check(option.Description)
		check(option.Category)
		check(configOptionLabels[option.Name])
	}
	for _, feature := range featureCatalog {
		check(feature.Title)
		check(feature.Description)
	}
	for _, example := range getBPFExamples() {
		check(example.Name)
		check(example.Description)
	}
	for _, description := range chartFieldDescriptions {
		check(description)
	}
	for _, label := range []string{"Packet decoder", "Packet decoder (gopacket)", "Stream decoder", "Abstract decoder", "Rule set {name} enabled ({count} rules affected)", "Rule set {name} disabled ({count} rules affected)", "Injection rule enabled", "Injection rule disabled", "Show alternatives enabled", "Show alternatives disabled", "Database download started", "A database download is already running"} {
		check(label)
	}
	messageFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range messageFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "requestUIMessage" || len(call.Args) < 3 {
				return true
			}
			if text, ok := call.Args[2].(*ast.BasicLit); ok && text.Kind == token.STRING {
				english, _ := strconv.Unquote(text.Value)
				check(english)
			}
			return true
		})
	}
	// Static chart titles and axis names must not silently escape the catalog.
	files, err := filepath.Glob("*_charts.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "behavior_topology.go")
	for _, path := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || (typ.Sel.Name != "Title" && !strings.HasSuffix(typ.Sel.Name, "Axis") && !strings.HasSuffix(typ.Sel.Name, "Axis3D")) {
				return true
			}
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok || (key.Name != "Title" && key.Name != "Name") {
					continue
				}
				value, ok := pair.Value.(*ast.BasicLit)
				if !ok || value.Kind != token.STRING {
					continue
				}
				english, _ := strconv.Unquote(value.Value)
				if english != "" {
					check(english)
				}
			}
			return true
		})
	}
}

func TestPresentationMessageParametersRemainLiteral(t *testing.T) {
	name := `Requests {count} </script> 捕获`
	for _, locale := range presentationLocales {
		message := requestUIMessage(httptest.NewRequest("GET", "/api/harvesters/presets?locale="+locale, nil), "harvester.preset.saved", "Preset '{name}' saved successfully", map[string]any{"name": name, "count": 7})
		if message.Params["name"] != name || !strings.Contains(message.Text, name) || strings.Contains(presentationJSON(message), "</script>") {
			t.Fatalf("%s translated or recursively substituted a user value: %+v", locale, message)
		}
	}
}

func TestPresentationMetadataPreservesLegacyAndSemanticValues(t *testing.T) {
	s := &Server{features: newFeatureSet(nil)}
	english := s.getConfigOptions(nil)
	localized := s.getConfigOptions(nil)
	p := Presentation{Theme: "light", Locale: "de"}
	presentConfigOptions(localized, p)
	for i, original := range english {
		got := localized[i]
		if got.Name != original.Name || fmt.Sprint(got.Value) != fmt.Sprint(original.Value) || got.Description != original.Description || got.Category != original.Category || got.IsEditable != original.IsEditable {
			t.Fatalf("config semantics/English changed: %+v vs %+v", got, original)
		}
		if got.DescriptionI18n.ID == "" || got.DescriptionI18n.Text == got.Description {
			t.Errorf("config description not localized: %s", got.Name)
		}
	}
	for i, example := range getBPFExamplesForPresentation(p) {
		original := getBPFExamples()[i]
		if example.Filter != original.Filter || example.Name != original.Name || example.Description != original.Description || example.ID == "" || example.NameI18n.ID == "" || example.NameI18n.Text == example.Name {
			t.Errorf("invalid BPF presentation: %+v", example)
		}
	}
	for _, locale := range presentationLocales {
		t.Run(locale, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleFeatures(w, httptest.NewRequest("GET", "/api/features?locale="+locale, nil))
			var result struct {
				Features []FeatureState `json:"features"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Features[0].TitleI18n.Text != (Presentation{Locale: locale}).text(result.Features[0].Title) || !s.features.Enabled(featureNetworkDetection) {
				t.Fatal("locale query changed feature state or failed to localize")
			}
		})
	}
	fields := ChartFieldsResponse{Fields: []ChartFieldInfo{{Name: "Size", Type: "numeric (integer)", Description: "Size in bytes"}, {Name: "RequestHeader.Size in bytes", Type: "categorical (string)", Description: "Size in bytes"}}}
	presentChartFields(&fields, p)
	if fields.Fields[0].DescriptionI18n.Text == "Size in bytes" || fields.Fields[1].DescriptionI18n.Text != "Size in bytes" || fields.Fields[1].DescriptionI18n.Params["field"] != "RequestHeader.Size in bytes" {
		t.Fatalf("field provenance lost: %+v", fields.Fields)
	}
}

func TestPresentationHTMLRequestIsolationCoverageAndCSP(t *testing.T) {
	for _, theme := range []string{"dark", "light"} {
		for _, locale := range presentationLocales {
			t.Run(theme+"/"+locale, func(t *testing.T) {
				t.Parallel()
				w := httptest.NewRecorder()
				request := httptest.NewRequest("GET", "/api/connections/protocols?theme="+theme+"&locale="+locale, nil)
				handler := chartCoverageMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					chart := generateConnectionsProtocolsChart([]ConnectionSummary{{TransportProto: "Requests"}, {}}, true)
					document, err := injectFullHeightCSSForRequest(chart.Render, r)
					if err != nil {
						t.Fatal(err)
					}
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write(document)
				}))
				handler.ServeHTTP(w, request)
				document := w.Body.String()
				if !strings.Contains(document, `"theme":"`+theme+`","locale":"`+locale+`"`) || w.Header().Get("Content-Language") != locale || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("request presentation not resolved: %+v", w.Header())
				}
				if strings.Count(document, `data-netcap-coverage="v1"`) != 1 || !strings.Contains(document, "netcap-coverage") || !strings.Contains(document, (Presentation{Locale: locale}).text("Retained audit summaries · sampling/completeness unreported · derived rates, not wire-volume measurements")) {
					t.Fatal("coverage annotation missing or duplicated")
				}
				if strings.Count(document, "<script") != strings.Count(document, "<script nonce=") || !strings.Contains(document, "window.netcapSetChart(goecharts_") {
					t.Fatal("presentation bypasses CSP or initial setOption")
				}
				if strings.LastIndex(document, `id="netcap-presentation"`) < strings.LastIndex(document, "background: #050508 !important") {
					t.Fatal("legacy dark CSS overrides request theme")
				}
			})
		}
	}
}

func TestPresentationChartErrorsAndNoDataRemainCompatible(t *testing.T) {
	for _, accept := range []string{"", "application/json", "text/html"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/chart/data?theme=light&locale=fr-CA", nil)
		r.Header.Set("Accept", accept)
		HandleChartData(t.TempDir())(w, r)
		if w.Code != 405 || w.Header().Get("X-Netcap-Error-Code") != "method_not_allowed" {
			t.Fatalf("error status/code lost: %d %v", w.Code, w.Header())
		}
		if accept == "" && w.Body.String() != "Method not allowed\n" {
			t.Fatalf("legacy diagnostic changed: %s", w.Body)
		}
		if accept == "application/json" && !strings.Contains(w.Body.String(), `"error":"Method not allowed"`) {
			t.Fatal("JSON removed legacy diagnostic")
		}
		if accept == "text/html" && !strings.Contains(w.Body.String(), "Méthode non autorisée") {
			t.Fatal("iframe error not localized")
		}
	}
	w := httptest.NewRecorder()
	HandleChartData(t.TempDir())(w, httptest.NewRequest("GET", "/api/chart/data?type=File&field=MagikaLabel&theme=light&locale=nl", nil))
	if w.Code != 204 || w.Body.Len() != 0 || w.Header().Get("X-Netcap-Error-Code") != "chart_no_data" {
		t.Fatalf("no-data contract changed: %d %s", w.Code, w.Body)
	}
	var coverage RenderedChartCoverage
	coverage.Selection, coverage.PointLimit, coverage.SourcesRequested = "prefix-of-usable-values", 17, 2
	for _, locale := range presentationLocales {
		text := coverage.textFor(Presentation{Locale: locale})
		if strings.Contains(text, "%!") || !strings.Contains(text, "17") || !strings.Contains(text, "0/2") {
			t.Fatalf("invalid parameterized coverage: %s", text)
		}
	}
	s := &Server{isServiceMode: true, sessionManager: &SessionManager{sessions: map[string]*SessionInfo{}}}
	selected := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/connections/protocols?sessionId=missing&locale=de", nil)
	request.Header.Set("Accept", "application/json")
	chartCoverageMiddleware(s.captureSelectionMiddleware(http.HandlerFunc(s.handleConnectionsProtocols))).ServeHTTP(selected, request)
	if selected.Code != http.StatusNotFound || selected.Header().Get("X-Netcap-Error-Code") == "" || !strings.Contains(selected.Body.String(), `"messageI18n"`) {
		t.Fatalf("selection error escaped the chart presentation boundary: %d %s", selected.Code, selected.Body)
	}
	classified := httptest.NewRecorder()
	chartCoverageMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uiHTTPError(w, r, "original bound diagnostic", 422, "chart_bucket_limit", "Chart exceeds the time-bucket limit", map[string]any{"limit": 17})
	})).ServeHTTP(classified, httptest.NewRequest("GET", "/api/chart/data", nil))
	if classified.Header().Get("X-Netcap-Error-Code") != "chart_bucket_limit" || classified.Body.String() != "original bound diagnostic\n" {
		t.Fatalf("response wrapper replaced a structured error code/diagnostic: %v %s", classified.Header(), classified.Body)
	}
}

func TestPresentationLabelProvenanceAndDataIdentity(t *testing.T) {
	labels := newChartLabelSet()
	if labels.name("", "Unknown") != "Unknown" || labels.label("Unknown") == nil {
		t.Fatal("synthesized missing value not marked")
	}
	if labels.name("Unknown", "Unknown") != "Unknown" || labels.label("Unknown") != nil {
		t.Fatal("literal record value was marked for translation")
	}
	for _, rows := range [][]ConnectionSummary{{{}}, {{TransportProto: "Unknown"}}, {{}, {TransportProto: "Unknown"}}} {
		chart := generateConnectionsProtocolsChart(rows, true)
		raw, err := renderChartSafe(chart.Render)
		if err != nil {
			t.Fatal(err)
		}
		marked := bytes.Contains(raw, []byte(`window.netcapOwnedLabel(`))
		if marked != (len(rows) == 1 && rows[0].TransportProto == "") {
			t.Fatalf("literal/fallback collision mishandled: %s", raw)
		}
	}
	chart := charts.NewPie()
	chart.AddSeries("Requests", []opts.PieData{{Name: "</script><img src=x onerror=alert(1)>", Value: 7}})
	document, err := injectFullHeightCSSForRequest(chart.Render, httptest.NewRequest("GET", "/api/http/methods?theme=light&locale=de", nil))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte("<img src=x")) || !bytes.Contains(document, []byte(`\u003c/script\u003e`)) {
		t.Fatal("presentation damaged script-context escaping")
	}
	reader := NewChartGenerator("HTTP", "RequestHeader.Requests", "pie", "", true, 10, Presentation{Theme: "light", Locale: "de"}).generatePieChart([]kvPair{{key: "Requests", value: 7}})
	got, _ := io.ReadAll(reader)
	if !bytes.Contains(got, []byte(`"field":{"auditType":"HTTP","field":"RequestHeader.Requests"`)) || !bytes.Contains(got, []byte(`"name":"Requests","value":7`)) {
		t.Fatal("generic chart lost field/capture identity")
	}
}

func TestPresentationPaletteTextContrast(t *testing.T) {
	luminance := func(color string) float64 {
		var channels [3]float64
		for i := range channels {
			n, err := strconv.ParseUint(color[1+2*i:3+2*i], 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			v := float64(n) / 255
			if v <= .04045 {
				channels[i] = v / 12.92
			} else {
				channels[i] = math.Pow((v+.055)/1.055, 2.4)
			}
		}
		return channels[0]*.2126 + channels[1]*.7152 + channels[2]*.0722
	}
	for name, palette := range chartPalettes {
		for _, bg := range []string{palette.Background, palette.Surface} {
			for _, fg := range []string{palette.Text, palette.Muted} {
				a, b := luminance(bg), luminance(fg)
				ratio := (math.Max(a, b) + .05) / (math.Min(a, b) + .05)
				if ratio < 4.5 {
					t.Errorf("%s %s/%s text contrast %.2f < 4.5", name, fg, bg, ratio)
				}
			}
		}
	}
}
