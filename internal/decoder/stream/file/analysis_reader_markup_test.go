package file

import (
	"strings"
	"testing"
)

// 30 HTML pages with inline script were reported as application/javascript,
// which fed File Type Mismatch and Document With Embedded Script noise.
func TestHTMLWithScriptStaysHTML(t *testing.T) {
	for content, want := range map[string]string{
		"<!DOCTYPE html><html><head><script>var x = function(){};</script></head></html>": "text/html",
		"<html><body onload=\"f()\"><script>const a = 1;</script></body></html>":         "text/html",
		"<?xml version=\"1.0\"?><root/>":                                                  "text/xml",
		"var x = 1;\nfunction f() { return x; }\n":                                        "application/javascript",
	} {
		facts := &artifactFacts{}
		facts.feed([]byte(content), 0)
		a, err := facts.analyze(strings.NewReader(content), "page.html")
		if err != nil {
			t.Fatal(err)
		}
		if a.TrueFileType != want {
			t.Errorf("%.30q: %s, want %s", content, a.TrueFileType, want)
		}
		memory := (&artifactData{bytes: []byte(content)})
		b, err := memory.Analyze("page.html")
		if err != nil || b.TrueFileType != want || b.TypeMismatch != a.TypeMismatch {
			t.Errorf("%.30q: in-memory analysis %+v (%v), spool analysis %+v", content, b, err, a)
		}
	}
}
