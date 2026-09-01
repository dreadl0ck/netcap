/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"strings"
)

// Cross-site scripting defence for server-rendered go-echarts charts.
//
// go-echarts serialises a chart's option object with HTML escaping explicitly
// DISABLED and marks the result as trusted, then writes it verbatim into an
// inline <script> block:
//
//	charts/base.go     JSONNotEscaped()  ->  enc.SetEscapeHTML(false)
//	                                         return template.HTML(...)
//	templates/base.tpl {{- .JSONNotEscaped | safeJS }}   inside <script>
//
// Every string netcap puts into a chart option therefore reaches a script
// context unescaped. Those strings are not ours: chart labels are field values
// lifted verbatim out of user-supplied capture files (HTTP User-Agent and Host,
// DNS query names, harvested credentials, TLS certificate subjects, ...), and
// chart titles interpolate raw query parameters. A label of
//
//	</script><img src=x onerror=alert(1)>
//
// closes the script element and executes. This was reachable both reflected
// (one GET, no upload) and stored (a poisoned capture file, which the dashboard
// then renders for every visitor because its default scope aggregates every
// session).
//
// The fix restores what Go's encoder does by default, at the point where the
// rendered HTML leaves go-echarts. It is deliberately NOT input sanitisation:
// \u003c decodes back to '<' when the browser parses the script, so labels
// still display byte-identically to what was on the wire. For a forensics tool
// that matters -- the whole point is to read the attacker's exact User-Agent,
// not an entity-mangled version of it.
//
// This mirrors enc.SetEscapeHTML(true) exactly, so if the one-line upstream
// change ever lands in go-echarts this layer becomes a redundant no-op rather
// than something that has to be unpicked.

// optionAssignPrefix is how go-echarts' base template opens the option literal:
//
//	let option_{{ .ChartID | safeJS }} = {{ template "base_option" . }}
//
// The encoded object follows on the same line, terminated by a newline, because
// json.Encoder.Encode emits a single line. A Page render repeats the pattern
// once per chart, so every occurrence is processed.
const optionAssignPrefix = "let option_"

// renderChartSafe renders a go-echarts chart and neutralises the script-context
// injection described above.
//
// All three chart wrappers in this package (injectFullHeightCSS,
// inject3DChartControls, renderChartWithFullHeight) route through here so that
// no render path can omit the escaping. Any new wrapper must do the same.
func renderChartSafe(renderFunc func(w io.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	if err := renderFunc(&buf); err != nil {
		return nil, err
	}

	return escapeChartOptionHTML(buf.Bytes()), nil
}

// escapeChartOptionHTML finds every `let option_… = <encoded object>` line in
// rendered chart HTML and escapes the HTML-significant characters that appear
// inside its JSON string literals.
//
// Scoping to the option line is what makes this safe: the surrounding document
// is real HTML whose tags legitimately contain '<'.
func escapeChartOptionHTML(html []byte) []byte {
	var (
		out    bytes.Buffer
		cursor int
	)

	out.Grow(len(html) + 64)

	for {
		rel := bytes.Index(html[cursor:], []byte(optionAssignPrefix))
		if rel < 0 {
			break
		}

		start := cursor + rel

		// The encoded object runs to the end of the line. If the template ever
		// stops emitting it on one line this finds no terminator and the tail
		// is escaped as one span, which is still correct.
		end := bytes.IndexByte(html[start:], '\n')
		if end < 0 {
			end = len(html)
		} else {
			end += start
		}

		out.Write(html[cursor:start])
		out.Write(escapeHTMLInJSONStrings(html[start:end]))

		cursor = end
	}

	out.Write(html[cursor:])

	return out.Bytes()
}

// escapeHTMLInJSONStrings replaces '<', '>' and '&' with their \u00XX form, but
// only where they occur inside a double-quoted string literal.
//
// Tracking string state rather than replacing blindly is the point. go-echarts
// puts raw JavaScript in the option object as well as data -- its word cloud
// emits an unquoted colour function -- and rewriting '<' to '\u003c' outside a
// string would turn `a < b` into a syntax error and blank the chart. netcap
// currently injects no raw JS of its own (every Formatter is a plain echarts
// template string), but a future FuncOpts must not silently break.
//
// Operating on bytes is safe for UTF-8: every byte of a multi-byte rune is
// >= 0x80, so it cannot be mistaken for one of the ASCII characters handled
// here. U+2028 and U+2029, the other two characters that can terminate a
// JavaScript line, need no handling because encoding/json always escapes them
// regardless of the SetEscapeHTML setting.
func escapeHTMLInJSONStrings(span []byte) []byte {
	var out bytes.Buffer

	out.Grow(len(span) + 32)

	var (
		inString bool
		escaped  bool
	)

	for i := 0; i < len(span); i++ {
		c := span[i]

		if !inString {
			if c == '"' {
				inString = true
			}

			out.WriteByte(c)

			continue
		}

		// Previous byte was a backslash, so this one is part of an escape
		// sequence and must be copied through untouched.
		if escaped {
			escaped = false

			out.WriteByte(c)

			continue
		}

		switch c {
		case '\\':
			escaped = true

			out.WriteByte(c)
		case '"':
			inString = false

			out.WriteByte(c)
		case '<':
			out.WriteString(`\u003c`)
		case '>':
			out.WriteString(`\u003e`)
		case '&':
			out.WriteString(`\u0026`)
		default:
			out.WriteByte(c)
		}
	}

	return out.Bytes()
}

// chartCSPNonce returns a fresh base64 nonce for one chart response.
//
// The nonce must be unpredictable, because it is the only thing distinguishing
// the inline scripts we emit from one an injected label might introduce.
func chartCSPNonce() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(b[:]), nil
}

// chartCSP builds the Content-Security-Policy for a rendered chart document.
//
// Only scripts carrying the nonce, plus same-origin script files, may run. That
// is what makes the policy worth having: an injected `<img src=x onerror=...>`
// or `<script>` cannot guess the nonce, so neither executes. Using
// 'unsafe-inline' instead would permit the injected script too and the policy
// would be decoration.
//
// Notes on the individual directives, all of which are needed by go-echarts and
// were confirmed against a real rendered chart rather than assumed:
//
//   - script-src 'self' covers /static/echarts/*.js; the nonce covers the
//     option block and netcap's injected resize helper.
//   - style-src needs 'unsafe-inline' for the <style> blocks and the style=""
//     attributes go-echarts writes on the chart container.
//   - img-src needs data: and blob: for the toolbox "Save as image" feature,
//     which exports the canvas.
//   - worker-src needs 'self' and blob: because echarts-gl, used by the 3D
//     charts, spawns workers; default-src 'none' would otherwise block them.
func chartCSP(nonce string) string {
	return strings.Join([]string{
		"default-src 'none'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:",
		"font-src 'self' data:",
		"connect-src 'self'",
		"worker-src 'self' blob:",
		"base-uri 'none'",
		"form-action 'none'",
		"object-src 'none'",
	}, "; ")
}

// finalizeChartHTML stamps a per-response nonce onto every inline script in a
// rendered chart document and installs a matching CSP.
//
// This must run LAST, after any wrapper has finished injecting its own scripts,
// or those scripts miss the nonce and the CSP blocks them. Each chart wrapper
// therefore calls it on the way out rather than it living in renderChartSafe.
//
// The policy is delivered as a <meta> element rather than a header because the
// chart HTML is produced deep inside ~60 handlers that each write their own
// response, and threading a nonce out to all of them through request context
// would be a far larger change than the vulnerability warrants. The tradeoff is
// that frame-ancestors is ignored when delivered by meta -- acceptable here,
// since framing is already constrained by the sandbox attribute the frontend
// puts on the iframe (see ChartFrame.tsx).
func finalizeChartHTML(html []byte) []byte {
	nonce, err := chartCSPNonce()
	if err != nil {
		// Without a nonce the only policies available either block our own
		// inline scripts (blank chart) or allow all inline script (no
		// protection). Emit no CSP and keep the chart working: the escaping in
		// escapeChartOptionHTML and the iframe sandbox are the enforcing
		// controls, and this is a defence-in-depth layer on top of them.
		log.Printf("[WebUI] chart: nonce generation failed, serving without CSP: %v", err)

		return html
	}

	// Attacker-controlled data has already been escaped by this point, so any
	// literal "<script" remaining is one we emitted. Note "</script" does not
	// match: the '<' there is followed by '/'.
	html = bytes.ReplaceAll(html, []byte("<script"), []byte(`<script nonce="`+nonce+`"`))

	meta := `<meta http-equiv="Content-Security-Policy" content="` + chartCSP(nonce) + `">`

	if i := bytes.Index(html, []byte("<head>")); i >= 0 {
		const headLen = len("<head>")

		var out bytes.Buffer

		out.Grow(len(html) + len(meta))
		out.Write(html[:i+headLen])
		out.WriteString(meta)
		out.Write(html[i+headLen:])

		return out.Bytes()
	}

	// No <head> to anchor to. Prepending still applies the policy to the
	// document, so prefer that over silently shipping none.
	return append([]byte(meta), html...)
}

// graphLayouts is the set of layouts the echarts graph series accepts.
var graphLayouts = map[string]bool{
	"circular": true,
	"force":    true,
	"none":     true,
}

// sanitizeGraphLayout constrains the caller-supplied ?layout= parameter to the
// values echarts actually understands, falling back to the previous default.
//
// This is defence in depth rather than the primary fix -- escapeChartOptionHTML
// already denies the injection -- but the parameter reaches the option object
// verbatim, so validating it keeps the reflected vector closed independently of
// the escaping layer, and an unrecognised layout was never anything but a
// silently broken chart.
func sanitizeGraphLayout(layout string) string {
	if graphLayouts[layout] {
		return layout
	}

	return "circular"
}
