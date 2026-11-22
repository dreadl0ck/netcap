package webui

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"

	"golang.org/x/text/language"
)

// Presentation is request-local. Its zero value is the legacy dark, English UI.
type Presentation struct {
	Theme  string `json:"theme"`
	Locale string `json:"locale"`
}

var presentationLocales = [...]string{"en", "de", "nl", "fr", "es", "zh-Hans"}

func presentationLocale(value string) string {
	if len(value) == 0 || len(value) > 35 {
		return "en"
	}
	tag, err := language.Parse(value)
	if err != nil {
		return "en"
	}
	base, _ := tag.Base()
	switch base.String() {
	case "de", "nl", "fr", "es":
		return base.String()
	case "zh":
		return "zh-Hans"
	default:
		return "en"
	}
}

func (p Presentation) normalized() Presentation {
	if p.Theme != "light" {
		p.Theme = "dark"
	}
	p.Locale = presentationLocale(p.Locale)
	return p
}

// PresentationFromRequest accepts one bounded value per key; malformed,
// duplicate and unsupported values fall back independently. Headers and saved
// preferences deliberately do not change this URL contract.
func PresentationFromRequest(r *http.Request) Presentation {
	p := Presentation{}
	if r != nil {
		q := r.URL.Query()
		if v := q["theme"]; len(v) == 1 && len(v[0]) <= 5 {
			p.Theme = v[0]
		}
		if v := q["locale"]; len(v) == 1 && len(v[0]) <= 35 {
			p.Locale = v[0]
		}
	}
	return p.normalized()
}

func (p Presentation) text(english string) string {
	index := 0
	locale := p.normalized().Locale
	for i, candidate := range presentationLocales {
		if locale == candidate {
			index = i
			break
		}
	}
	if row, ok := chartPresentationCatalog[english]; ok {
		return row[index]
	}
	if row, ok := metadataPresentationCatalog[english]; ok {
		return row[index]
	}
	return english
}

// UIMessage accompanies legacy English fields. IDs and parameters are stable;
// text is already resolved for clients that do not own a matching catalog.
type UIMessage struct {
	ID     string         `json:"id"`
	Params map[string]any `json:"params,omitempty"`
	Text   string         `json:"text"`
}

func (p Presentation) message(id, english string, params map[string]any) UIMessage {
	text := p.text(english)
	if len(params) > 0 {
		replacements := make([]string, 0, len(params)*2)
		for key, value := range params {
			replacements = append(replacements, "{"+key+"}", fmt.Sprint(value))
		}
		text = strings.NewReplacer(replacements...).Replace(text)
	}
	return UIMessage{ID: id, Params: params, Text: text}
}

func requestUIMessage(r *http.Request, id, english string, params map[string]any) UIMessage {
	return PresentationFromRequest(r).message(id, english, params)
}

func presentationHeaders(w http.ResponseWriter, p Presentation) {
	p = p.normalized()
	w.Header().Set("Content-Language", p.Locale)
	w.Header().Set("X-Netcap-Theme", p.Theme)
	// Only semantic snapshots are cached; rendered presentation is never cached.
	w.Header().Set("Cache-Control", "no-store")
}

// uiHTTPError preserves the English diagnostic and status for existing clients.
// JSON is opt-in; iframe navigations receive localized, escaped error chrome.
func uiHTTPError(w http.ResponseWriter, r *http.Request, diagnostic string, status int, code, english string, parameters ...map[string]any) {
	p := PresentationFromRequest(r)
	presentationHeaders(w, p)
	w.Header().Set("X-Netcap-Error-Code", code)
	w.Header().Set("X-Netcap-Message-ID", "webui."+code)
	message := p.message("webui."+code, english, nil)
	if len(parameters) > 0 {
		message.Params = parameters[0]
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		RespondJSON(w, status, map[string]any{"error": diagnostic, "code": code, "messageI18n": message})
		return
	}
	if strings.Contains(accept, "text/html") {
		body := `<!doctype html><html><head><meta charset="utf-8"></head><body><p role="alert" data-netcap-error="` + code + `">` + html.EscapeString(message.Text) + `</p><details><summary data-netcap-diagnostic>` + html.EscapeString(p.text("Diagnostic details")) + `</summary><pre>` + html.EscapeString(diagnostic) + `</pre></details></body></html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(finalizeChartHTML(presentChartHTML([]byte(body), chartPresentation{Presentation: p, Error: english})))
		return
	}
	http.Error(w, diagnostic, status)
}

func chartHTTPError(w http.ResponseWriter, r *http.Request, diagnostic string, status int) {
	code, english := "chart_unavailable", "Chart unavailable"
	switch diagnostic {
	case "Method not allowed", "method not allowed":
		code, english = "method_not_allowed", "Method not allowed"
	case "No output directory set":
		code, english = "chart_no_output", "No output directory set"
	case "Failed to generate chart", "topology render failed":
		code, english = "chart_render_failed", "Failed to generate chart"
	case "Failed to read HTTP records":
		code, english = "chart_read_failed", "Failed to read chart records"
	case "Missing required parameters: type, field", "Missing required parameter: type", "Unknown audit type":
		code, english = "chart_invalid_request", "Invalid chart request"
	case "chart analysis is busy":
		code, english = "chart_busy", "Chart analysis is busy"
	}
	uiHTTPError(w, r, diagnostic, status, code, english)
}

func chartNoData(w http.ResponseWriter, r *http.Request) {
	presentationHeaders(w, PresentationFromRequest(r))
	w.Header().Set("X-Netcap-Error-Code", "chart_no_data")
	w.Header().Set("X-Netcap-Message-ID", "webui.chart_no_data")
	w.WriteHeader(http.StatusNoContent)
}

func presentationJSON(value any) string {
	// encoding/json's HTML escaping is required for every inline script payload.
	data, _ := json.Marshal(value)
	return string(data)
}
