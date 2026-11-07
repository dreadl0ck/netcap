package webtech

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

type Result struct {
	ID        string `json:"id"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Precision string `json:"precision"`
}
type Observation struct {
	Method      string
	Status      int
	ContentType string
	Generator   []string
	Body        []byte
	BodyState   string
}
type Report struct {
	BodyState           string   `json:"body_state"`
	Matches             []Result `json:"matches"`
	DetectedContentType string   `json:"-"`
	WireBytes           int64    `json:"-"`
}

type countingReader struct {
	io.Reader
	n int64
}

func (r *countingReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	r.n += int64(n)
	return n, e
}

var reserved atomic.Int64

// ObserveReader drains the wire body without retaining it. The lease includes input,
// output and a codec reservation; concurrent capture fails visibly at 16 MiB.
func (e *Engine) ObserveReader(o Observation, body io.Reader, encoding string) Report {
	const lease = 1 << 20
	for {
		n := reserved.Load()
		if n+lease > MaxAggregate {
			drained, _ := io.Copy(io.Discard, body)
			o.BodyState = "budget-exhausted"
			r := e.Observe(o)
			r.WireBytes = drained
			return r
		}
		if reserved.CompareAndSwap(n, n+lease) {
			break
		}
	}
	defer reserved.Add(-lease)
	r := &countingReader{Reader: body}
	o.Body, o.BodyState = capture(r, encoding)
	report := e.Observe(o)
	report.WireBytes = r.n
	if o.Body != nil {
		report.DetectedContentType = http.DetectContentType(o.Body)
	}
	return report
}
func capture(body io.Reader, encoding string) ([]byte, string) {
	wire, err := io.ReadAll(io.LimitReader(body, MaxPrefix+1))
	overflow := len(wire) > MaxPrefix
	if overflow {
		wire = wire[:MaxPrefix]
	}
	// Drain to retain HTTP message framing; no body-sized allocation.
	_, drainErr := io.Copy(io.Discard, body)
	state := "complete"
	if overflow {
		state = "truncated"
	}
	if err != nil || drainErr != nil {
		state = "incomplete"
	}
	var reader io.Reader = bytes.NewReader(wire)
	var closer io.Closer
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
	case "gzip":
		r, e := gzip.NewReader(reader)
		if e != nil {
			return nil, "decode-failed"
		}
		r.Multistream(false)
		reader = r
		closer = r
	case "deflate":
		r, e := zlib.NewReader(reader)
		if e != nil {
			return nil, "decode-failed"
		}
		reader = r
		closer = r
	default:
		return nil, "unsupported-encoding"
	}
	if closer != nil {
		defer closer.Close()
	}
	out, e := io.ReadAll(io.LimitReader(reader, MaxPrefix+1))
	if len(out) > MaxPrefix {
		out = out[:MaxPrefix]
		state = "truncated"
	} else if e != nil {
		return nil, "decode-failed"
	}
	return out, state
}

func (e *Engine) Observe(o Observation) Report {
	r := Report{BodyState: o.BodyState, Matches: []Result{}}
	if r.BodyState == "" {
		r.BodyState = "unobservable"
	}
	if o.Method != "GET" || o.Status != 200 {
		r.BodyState = "out-of-scope"
		return r
	}
	meta := []string{}
	mime := strings.ToLower(strings.TrimSpace(strings.Split(o.ContentType, ";")[0]))
	if mime == "text/html" || mime == "application/xhtml+xml" {
		if o.BodyState == "complete" || o.BodyState == "truncated" || o.BodyState == "incomplete" {
			b := o.Body
			if len(b) > MaxPrefix {
				b = b[:MaxPrefix]
				r.BodyState = "truncated"
			}
			var limited bool
			if !utf8.Valid(b) {
				r.BodyState = "unsupported-text"
			} else {
				meta, limited = generators(b)
				if limited {
					r.BodyState = "tag-limited"
				}
			}
		}
	} else {
		r.BodyState = "not-html"
	}
	for _, rule := range e.catalogue.Rules {
		values := meta
		if rule.Selector == "x-generator" {
			values = o.Generator
		}
		for _, v := range values {
			if version, ok := token(rule, v); ok {
				precision := rule.Precision
				if version == "" {
					precision = "none"
				}
				r.Matches = append(r.Matches, Result{rule.ID, rule.Product, version, precision})
				break
			}
		}
	}
	return r
}
func token(r Rule, v string) (string, bool) {
	if len(v) > MaxTag || !strings.HasPrefix(v, r.Token) {
		return "", false
	}
	rest := v[len(r.Token):]
	if rest != "" && rest[0] != ' ' {
		return "", false
	}
	rest = strings.Trim(rest, " \t\r\n")
	if r.Precision == "none" {
		return "", true
	}
	if rest == "" {
		return "", true
	}
	end := strings.IndexAny(rest, " \t\r\n")
	if end >= 0 {
		rest = rest[:end]
	}
	if len(rest) > 32 || rest == "" {
		return "", false
	}
	for _, part := range strings.Split(rest, ".") {
		if part == "" {
			return "", false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return "", false
			}
		}
	}
	if r.Precision == "major" {
		rest = strings.Split(rest, ".")[0]
	}
	return rest, true
}

// generators is deliberately a small lexical HTML subset. It does not inspect
// comments, raw-text elements, templates or external resources.
func generators(body []byte) ([]string, bool) {
	b := string(body)
	lower := append([]byte{}, body...)
	for i, c := range lower {
		if c >= 'A' && c <= 'Z' {
			lower[i] = c + 32
		}
	}
	low := string(lower)
	out := []string{}
	limited := false
	for i := 0; i < len(b); {
		n := strings.IndexByte(b[i:], '<')
		if n < 0 {
			break
		}
		i += n
		if strings.HasPrefix(low[i:], "<!--") {
			j := strings.Index(low[i+4:], "-->")
			if j < 0 {
				break
			}
			i += 4 + j + 3
			continue
		}
		end := i + 1
		var quote byte
		for ; end < len(b) && end-i < MaxTag; end++ {
			c := b[end]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
			} else if c == '\'' || c == '"' {
				quote = c
			} else if c == '>' {
				break
			}
		}
		if end >= len(b) || end-i >= MaxTag {
			limited = true
			break
		}
		tag := b[i+1 : end]
		i = end + 1
		name, attrs := attributes(tag)
		switch name {
		case "template", "plaintext":
			return out, true
		case "script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript":
			for {
				j := strings.Index(low[i:], "</"+name)
				if j < 0 {
					return out, limited
				}
				i += j
				next := i + 2 + len(name)
				if next == len(b) || space(b[next]) || b[next] == '>' || b[next] == '/' {
					break
				}
				i = next
			}
		case "meta":
			if strings.EqualFold(attrs["name"], "generator") {
				if v, ok := attrs["content"]; ok {
					out = append(out, v)
				}
			}
		}
	}
	return out, limited
}
func space(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' }
func attributes(tag string) (string, map[string]string) {
	a := map[string]string{}
	i := 0
	for i < len(tag) && !space(tag[i]) && tag[i] != '/' {
		i++
	}
	name := strings.ToLower(tag[:i])
	for i < len(tag) {
		for i < len(tag) && (space(tag[i]) || tag[i] == '/') {
			i++
		}
		start := i
		for i < len(tag) && !space(tag[i]) && tag[i] != '=' && tag[i] != '/' {
			i++
		}
		if start == i {
			break
		}
		key := strings.ToLower(tag[start:i])
		for i < len(tag) && space(tag[i]) {
			i++
		}
		value := ""
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && space(tag[i]) {
				i++
			}
			if i == len(tag) {
				break
			}
			q := byte(0)
			if tag[i] == '\'' || tag[i] == '"' {
				q = tag[i]
				i++
			}
			start = i
			for i < len(tag) && ((q != 0 && tag[i] != q) || (q == 0 && !space(tag[i]))) {
				i++
			}
			value = tag[start:i]
			if q != 0 && i < len(tag) {
				i++
			}
		}
		if _, ok := a[key]; ok {
			return "", nil
		}
		a[key] = value
	}
	return name, a
}
