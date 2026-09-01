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
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// scriptBreakout is the shape of payload that actually works against a
// go-echarts chart: the option object sits inside <script>, so closing the
// element is enough and no quote needs to be escaped first.
const scriptBreakout = `</script><img src=x onerror=alert('vulnerable')>`

func TestEscapeHTMLInJSONStringsNeutralisesBreakout(t *testing.T) {
	in := `{"data":[{"name":"` + scriptBreakout + `","value":1}]}`

	got := string(escapeHTMLInJSONStrings([]byte(in)))

	if strings.Contains(got, "</script>") {
		t.Fatalf("literal </script> survived escaping: %s", got)
	}

	if strings.Contains(got, "<img") {
		t.Fatalf("literal <img survived escaping: %s", got)
	}

	if !strings.Contains(got, `\u003c/script\u003e`) {
		t.Fatalf("expected \\u003c escaping, got: %s", got)
	}
}

// The escaper must not touch characters outside string literals. go-echarts
// emits raw JavaScript into the option object (its word cloud colour function),
// and rewriting '<' there would be a syntax error that blanks the chart.
func TestEscapeHTMLInJSONStringsLeavesRawJSAlone(t *testing.T) {
	in := `{"f":function () {if (a < b && c > d) {return '<';}},"name":"x<y"}`

	got := string(escapeHTMLInJSONStrings([]byte(in)))

	if !strings.Contains(got, "a < b && c > d") {
		t.Fatalf("raw JS operators were escaped, this would break the chart: %s", got)
	}

	// The '<' inside the single-quoted JS string is not in a JSON string as far
	// as this scanner is concerned, so it is left alone -- that is correct and
	// safe, because it cannot terminate the surrounding <script> element.
	if !strings.Contains(got, `"x\u003cy"`) {
		t.Fatalf("data string was not escaped: %s", got)
	}
}

func TestEscapeHTMLInJSONStringsHandlesEscapesAndUTF8(t *testing.T) {
	// A backslash-escaped quote must not be read as the end of the string, or
	// everything after it would be treated as raw JS and left unescaped.
	in := `{"a":"he said \"<b>\" loudly","b":"naïve <ü>","c":"back\\slash <x>"}`

	got := string(escapeHTMLInJSONStrings([]byte(in)))

	for _, want := range []string{
		`he said \"\u003cb\u003e\"`,
		`naïve \u003cü\u003e`,
		`back\\slash \u003cx\u003e`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got: %s", want, got)
		}
	}

	if strings.Contains(got, "<") {
		t.Fatalf("an unescaped < remains: %s", got)
	}
}

// escapeChartOptionHTML is scoped to the option assignment line. The document
// around it is real HTML whose tags must survive untouched.
func TestEscapeChartOptionHTMLOnlyRewritesTheOptionLine(t *testing.T) {
	in := `<html><head><script src="/static/echarts/echarts.min.js"></script></head>
<body><div class="item" id="abc"></div>
<script type="text/javascript">
    let option_abc = {"series":[{"name":"` + scriptBreakout + `"}]}
    goecharts_abc.setOption(option_abc);
</script></body></html>`

	got := string(escapeChartOptionHTML([]byte(in)))

	// Structural HTML preserved.
	for _, want := range []string{
		`<html><head><script src="/static/echarts/echarts.min.js"></script></head>`,
		`<body><div class="item" id="abc"></div>`,
		`<script type="text/javascript">`,
		`    goecharts_abc.setOption(option_abc);`,
		`</script></body></html>`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("structural HTML was altered, missing %q:\n%s", want, got)
		}
	}

	// Payload neutralised.
	if strings.Contains(got, scriptBreakout) {
		t.Fatalf("payload survived on the option line:\n%s", got)
	}

	if !strings.Contains(got, `\u003c/script\u003e`) {
		t.Fatalf("option line was not escaped:\n%s", got)
	}
}

func TestEscapeChartOptionHTMLHandlesMultipleCharts(t *testing.T) {
	in := `    let option_one = {"n":"` + scriptBreakout + `"}
    let option_two = {"n":"` + scriptBreakout + `"}
`

	got := string(escapeChartOptionHTML([]byte(in)))

	if n := strings.Count(got, `\u003c/script\u003e`); n != 2 {
		t.Fatalf("expected both option lines escaped, got %d:\n%s", n, got)
	}

	if strings.Contains(got, "</script>") {
		t.Fatalf("a payload survived:\n%s", got)
	}
}

// End-to-end through the real go-echarts renderer and each of the three
// wrappers in this package. This is the test that would have caught the
// original bug: it asserts on what a browser actually receives.
func TestChartWrappersEscapeAttackerControlledLabels(t *testing.T) {
	newWordCloud := func() *charts.WordCloud {
		wc := charts.NewWordCloud()
		wc.AddSeries("wordcloud", []opts.WordCloudData{
			// Stands in for an HTTP User-Agent lifted out of a capture file.
			{Name: scriptBreakout, Value: 99},
		})

		return wc
	}

	t.Run("renderChartSafe", func(t *testing.T) {
		got, err := renderChartSafe(newWordCloud().Render)
		if err != nil {
			t.Fatalf("render failed: %v", err)
		}

		assertNoBreakout(t, string(got))
	})

	t.Run("injectFullHeightCSS", func(t *testing.T) {
		got, err := injectFullHeightCSS(newWordCloud().Render)
		if err != nil {
			t.Fatalf("render failed: %v", err)
		}

		assertNoBreakout(t, string(got))
	})

	t.Run("inject3DChartControls", func(t *testing.T) {
		got, err := inject3DChartControls(newWordCloud().Render)
		if err != nil {
			t.Fatalf("render failed: %v", err)
		}

		assertNoBreakout(t, string(got))
	})

	t.Run("renderChartWithFullHeight", func(t *testing.T) {
		got, err := io.ReadAll(renderChartWithFullHeight(newWordCloud().Render))
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}

		assertNoBreakout(t, string(got))
	})
}

// assertNoBreakout checks that the payload cannot terminate the inline script.
//
// Note what is deliberately NOT asserted: the substring "onerror=alert(...)"
// is still present in the output, and that is correct. Only '<', '>' and '&'
// are escaped, so the payload survives as readable but inert text inside a
// quoted JSON string -- it has no way to become markup. Preserving it is the
// point: an analyst needs to see the exact bytes that were on the wire, and
// escaping the whole label would defeat the tool. What must not survive is a
// character sequence that can close the <script> element or open a tag.
func assertNoBreakout(t *testing.T, html string) {
	t.Helper()

	if strings.Contains(html, `<img src=x`) {
		t.Fatalf("injected tag survived:\n%s", html)
	}

	if !strings.Contains(html, `\u003c/script\u003e`) {
		t.Fatalf("expected the label to be unicode-escaped, it was not:\n%s", html)
	}

	// The option object must still be syntactically intact: go-echarts' own
	// word cloud colour function relies on unescaped operators.
	if !strings.Contains(html, "Math.random()") {
		t.Fatalf("go-echarts raw JS was damaged by escaping:\n%s", html)
	}
}

// The CSP is only worth anything if the nonce it names is actually on our
// scripts and unguessable. Verified end-to-end in headless Chrome when this was
// written: with the policy removed an injected inline script and an onerror
// handler both executed (document.title became "PWNED-HANDLER"); with it in
// place neither ran and the chart still drew its canvas.
func TestFinalizeChartHTMLInstallsNonceAndCSP(t *testing.T) {
	in := []byte(`<html><head><title>t</title></head><body>` +
		`<script src="/static/echarts/echarts.min.js"></script>` +
		`<script type="text/javascript">let option_a = {"n":"x"}` + "\n" +
		`</script></body></html>`)

	got := string(finalizeChartHTML(in))

	// Every script tag we emit must carry the nonce, external ones included --
	// script-src lists 'self' as well, but a uniform stamp is one less thing to
	// reason about.
	if n := strings.Count(got, "<script nonce="); n != 2 {
		t.Fatalf("expected 2 nonced script tags, got %d:\n%s", n, got)
	}

	if strings.Contains(got, "<script>") || strings.Contains(got, "<script src=") {
		t.Fatalf("a script tag escaped noncing:\n%s", got)
	}

	if !strings.Contains(got, `<meta http-equiv="Content-Security-Policy"`) {
		t.Fatalf("no CSP meta element:\n%s", got)
	}

	// The nonce in the policy must be the nonce on the tags.
	nonce := between(t, got, `<script nonce="`, `"`)
	if nonce == "" {
		t.Fatal("could not extract nonce")
	}

	if !strings.Contains(got, "'nonce-"+nonce+"'") {
		t.Fatalf("policy nonce does not match tag nonce %q:\n%s", nonce, got)
	}

	// 'unsafe-inline' in script-src would readmit the injected script and make
	// the whole layer pointless.
	scriptSrc := between(t, got, "script-src ", ";")
	if strings.Contains(scriptSrc, "unsafe-inline") {
		t.Fatalf("script-src must not allow unsafe-inline, got %q", scriptSrc)
	}

	if !strings.Contains(got, "object-src 'none'") || !strings.Contains(got, "base-uri 'none'") {
		t.Fatalf("expected object-src and base-uri lockdown:\n%s", got)
	}
}

func TestFinalizeChartHTMLNonceIsPerResponse(t *testing.T) {
	in := []byte(`<html><head></head><body><script>x</script></body></html>`)

	a := between(t, string(finalizeChartHTML(in)), `<script nonce="`, `"`)
	b := between(t, string(finalizeChartHTML(in)), `<script nonce="`, `"`)

	if a == "" || b == "" {
		t.Fatal("nonce missing")
	}

	if a == b {
		t.Fatalf("nonce was reused across responses (%q): a predictable nonce is no nonce", a)
	}
}

// Escaping must run before noncing, otherwise a label containing the literal
// text "<script" would be handed a valid nonce by the stamping pass.
func TestPayloadCannotAcquireANonce(t *testing.T) {
	wc := charts.NewWordCloud()
	wc.AddSeries("wordcloud", []opts.WordCloudData{
		{Name: `<script>alert('vulnerable')</script>`, Value: 1},
	})

	got, err := injectFullHeightCSS(wc.Render)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}

	// Two legitimate script tags exist in the wrapped output (the injected
	// resize helper and the option block) plus the asset tags. What must not
	// appear is a nonce attached to anything originating in the label.
	if strings.Contains(string(got), `alert('vulnerable')</script>`) {
		t.Fatalf("label was not escaped before noncing:\n%s", got)
	}

	if !strings.Contains(string(got), `\u003cscript\u003e`) {
		t.Fatalf("expected the label's tags to be escaped:\n%s", got)
	}
}

// between returns the substring of s between the first occurrence of pre and
// the next occurrence of suf after it.
func between(t *testing.T, s, pre, suf string) string {
	t.Helper()

	i := strings.Index(s, pre)
	if i < 0 {
		return ""
	}

	rest := s[i+len(pre):]

	j := strings.Index(rest, suf)
	if j < 0 {
		return ""
	}

	return rest[:j]
}

func TestSanitizeGraphLayout(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
	}{
		{"circular", "circular"},
		{"force", "force"},
		{"none", "none"},
		{"", "circular"},
		{"bogus", "circular"},
		// The reflected vector, verified live against try.netcap.io before the
		// fix: ?layout= landed in the option object verbatim.
		{scriptBreakout, "circular"},
		{`circular"}]}` + scriptBreakout, "circular"},
		{"CIRCULAR", "circular"},
	} {
		if got := sanitizeGraphLayout(tt.in); got != tt.want {
			t.Errorf("sanitizeGraphLayout(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizePcapFilename(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
	}{
		// Ordinary names survive intact, extension included -- the whole point
		// of not reusing sanitizeFilename, which would give "bgp_pcap".
		{"bgp.pcap", "bgp.pcap"},
		{"Hancitor-malspam-1st-run.pcap", "Hancitor-malspam-1st-run.pcap"},
		{"ultimate-PCAP-v20250325.pcapng", "ultimate-PCAP-v20250325.pcapng"},

		// HTML metacharacters cannot reach a rendering context.
		{`</script><img src=x onerror=alert(1)>.pcap`, "script__img_src_x_onerror_alert_1__.pcap"},
		{`a"b'c.pcap`, "a_b_c.pcap"},

		// Path traversal, on either OS's separator.
		{"../../etc/passwd.pcap", "passwd.pcap"},
		{`..\..\windows\system32.pcap`, "system32.pcap"},
		{`C:\Users\bob\capture.pcap`, "capture.pcap"},
		{"/absolute/path.pcap", "path.pcap"},

		// Hidden files and bare dots.
		{".hidden.pcap", "hidden.pcap"},
		{"..", "upload.pcap"},
		{".", "upload.pcap"},
		{"", "upload.pcap"},

		// Whitespace and control bytes.
		{"my capture.pcap", "my_capture.pcap"},
		{"line\nbreak.pcap", "line_break.pcap"},
		{"tab\there.pcap", "tab_here.pcap"},
	} {
		if got := sanitizePcapFilename(tt.in); got != tt.want {
			t.Errorf("sanitizePcapFilename(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizePcapFilenameIsBounded(t *testing.T) {
	got := sanitizePcapFilename(strings.Repeat("a", 400) + ".pcap")

	if len(got) > 128 {
		t.Errorf("length %d exceeds the 128-byte bound", len(got))
	}

	if !strings.HasSuffix(got, ".pcap") {
		t.Errorf("truncation dropped the extension: %q", got)
	}
}

// The sanitiser must never emit something that walks out of the uploads
// directory once joined onto a path.
func TestSanitizePcapFilenameCannotEscape(t *testing.T) {
	for _, in := range []string{
		"../../../etc/shadow.pcap", "....//....//x.pcap", "/etc/passwd",
		`..\..\..\x.pcap`, "..", "../", "./../x.pcap",
	} {
		got := sanitizePcapFilename(in)

		if strings.ContainsAny(got, `/\`) {
			t.Errorf("sanitizePcapFilename(%q) = %q still contains a separator", in, got)
		}

		if got == ".." || strings.HasPrefix(got, "..") {
			t.Errorf("sanitizePcapFilename(%q) = %q can traverse upward", in, got)
		}

		joined := filepath.Join("/data/uploads", got)
		if !strings.HasPrefix(joined, "/data/uploads/") {
			t.Errorf("sanitizePcapFilename(%q) = %q escaped the uploads dir: %s", in, got, joined)
		}
	}
}
