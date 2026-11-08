package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

func escapeTargetControls(target string) string {
	var out strings.Builder
	for i := 0; i < len(target); i++ {
		b := target[i]
		if b < 32 || b == 127 {
			fmt.Fprintf(&out, "%%%02X", b)
		} else {
			out.WriteByte(b)
		}
	}
	return out.String()
}

type replayBodyReader struct {
	io.Reader
	remaining int64
	chunked   bool
}

func (r *replayBodyReader) Read(p []byte) (int, error) {
	if r.chunked {
		// The chunk parser owns trailers too; do not prefetch a following message.
		if len(p) > 1 {
			p = p[:1]
		}
	} else if r.remaining >= 0 {
		if r.remaining == 0 {
			return 0, io.EOF
		}
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
	}
	n, err := r.Reader.Read(p)
	if !r.chunked && r.remaining >= 0 {
		r.remaining -= int64(n)
	}
	return n, err
}

const maxHTTPHeaders = 64 << 10
const maxHTTPHeaderCount = 256

var errUnsafeHTTPFraming = errors.New("ambiguous HTTP framing; direction stopped")

type messageEvidence struct {
	line    []byte
	headers []*types.HTTPHeaderEvidence
	issues  []string
	unsafe  bool
}

func (e *messageEvidence) issue(s string) { e.issues = appendUnique(e.issues, s) }

func (e *messageEvidence) framingError() error {
	if !e.unsafe {
		return nil
	}
	for _, issue := range e.issues {
		if issue == "incomplete-http-headers" {
			return io.ErrUnexpectedEOF
		}
	}
	return errUnsafeHTTPFraming
}

func appendUnique(dst []string, values ...string) []string {
	for _, value := range values {
		if value == "" {
			continue
		}
		found := false
		for _, old := range dst {
			if old == value {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, value)
		}
	}
	return dst
}

func addStatus(record *types.HTTP, value string) {
	record.ReassemblyStatus = strings.Join(appendUnique(strings.FieldsFunc(record.ReassemblyStatus, func(r rune) bool { return r == ',' }), value), ",")
}

// Only the outer whitespace is normalized; the exact target remains evidence.
func requestLine(line []byte) (method, target, version string, issues []string, ok bool) {
	s := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	method, rest, found := strings.Cut(s, " ")
	if !found || len(s) > 8192 {
		return
	}
	known := false
	for _, m := range httpMethods {
		if method == string(m) {
			known = true
			break
		}
	}
	if !known {
		return
	}
	for _, v := range []string{"HTTP/1.0", "HTTP/1.1"} {
		if strings.HasSuffix(rest, " "+v) {
			version = v
			target = strings.TrimSuffix(rest, " "+v)
			break
		}
	}
	if version == "" {
		// Missing-version evidence requires an origin-form target, not arbitrary text.
		if !strings.HasPrefix(rest, "/") || strings.ContainsAny(rest, " \t") {
			return
		}
		target = rest
		issues = append(issues, "missing-http-version")
	}
	trimmed := strings.Trim(target, " \t")
	if trimmed != target {
		issues = append(issues, "nonstandard-request-line-spacing")
	}
	target = trimmed
	if strings.ContainsAny(target, " \t") {
		issues = append(issues, "request-target-whitespace")
	}
	clean := escapeTargetControls(target)
	if clean != target {
		issues = append(issues, "invalid-request-target-control-byte")
	}
	if target == "" {
		return
	}
	if method == methodCONNECT {
		_, err := http.NewRequest(method, clean, nil)
		ok = err == nil
	} else {
		_, err := url.ParseRequestURI(strings.ReplaceAll(clean, " ", "%20"))
		ok = err == nil
	}
	return
}

func readEvidenceHead(b *bufio.Reader) (messageEvidence, http.Header, error) {
	e := messageEvidence{}
	header := make(http.Header)
	line, err := b.ReadSlice('\n')
	e.line = bytes.Clone(line)
	if err != nil {
		return e, header, err
	}
	total := len(line)
	for {
		line, err = b.ReadSlice('\n')
		total += len(line)
		if total > maxHTTPHeaders || len(e.headers) >= maxHTTPHeaderCount || err == bufio.ErrBufferFull {
			e.issue("http-header-limit")
			e.unsafe = true
			return e, header, nil
		}
		if len(line) == 0 || bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			if err != nil {
				e.issue("incomplete-http-headers")
				e.unsafe = true
			}
			return e, header, nil
		}
		raw := bytes.Clone(line)
		text := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
		name, value, valid := bytes.Cut(text, []byte(":"))
		item := &types.HTTPHeaderEvidence{Raw: raw, Name: bytes.Clone(name), Value: bytes.Clone(value)}
		e.headers = append(e.headers, item)
		if !valid || !validHeaderName(string(name)) || bytes.ContainsAny(value, "\x00\r\n") {
			e.issue("invalid-http-header")
			e.unsafe = true
		} else {
			header.Add(string(name), strings.Trim(string(value), " \t"))
		}
		if err != nil {
			e.issue("incomplete-http-headers")
			e.unsafe = true
			return e, header, nil
		}
	}
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func qualifyFraming(e *messageEvidence, header http.Header) {
	cl, te := header.Values("Content-Length"), header.Values("Transfer-Encoding")
	if len(cl) > 1 {
		e.issue("duplicate-content-length")
	}
	for _, value := range cl {
		_, err := strconv.ParseUint(value, 10, 63)
		if err != nil || value == "" || strings.Trim(value, "0123456789") != "" || value != cl[0] {
			e.issue("ambiguous-content-length")
			e.unsafe = true
		}
	}
	if len(te) > 0 && (len(te) != 1 || !strings.EqualFold(te[0], "chunked")) {
		e.issue("ambiguous-transfer-encoding")
		e.unsafe = true
	}
	if len(te) > 0 && len(cl) > 0 {
		e.issue("transfer-encoding-with-content-length")
		e.unsafe = true
	}
}

func readEvidenceRequest(b *bufio.Reader) (*http.Request, messageEvidence, error) {
	e, header, err := readEvidenceHead(b)
	if err != nil {
		return nil, e, err
	}
	method, target, version, issues, ok := requestLine(e.line)
	if !ok {
		return nil, e, errors.New("invalid HTTP request line")
	}
	e.issues = append(e.issues, issues...)
	qualifyFraming(&e, header)
	cleanTarget := strings.ReplaceAll(escapeTargetControls(target), " ", "%20")
	parseVersion := version
	if parseVersion == "" {
		parseVersion = "HTTP/1.0"
	}
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "%s %s %s\r\n", method, cleanTarget, parseVersion)
	for _, field := range e.headers {
		if !e.unsafe {
			wire.Write(field.Raw)
		}
	}
	wire.WriteString("\r\n")
	tail := &replayBodyReader{Reader: b}
	r, parseErr := http.ReadRequest(bufio.NewReader(io.MultiReader(&wire, tail)))
	if parseErr != nil {
		e.issue("strict-http-parser-rejected")
		e.unsafe = true
		u, _ := url.ParseRequestURI(cleanTarget)
		if u == nil {
			u = &url.URL{Path: target}
		}
		r = &http.Request{Method: method, URL: u, Body: http.NoBody}
	}
	r.Header, r.RequestURI, r.Proto = header, target, version
	if r.Host == "" {
		r.Host = header.Get("Host")
		if r.Host == "" {
			r.Host = r.URL.Host
		}
	}
	if e.unsafe {
		r.Body = http.NoBody
		r.ContentLength = -1
	}
	tail.remaining, tail.chunked = r.ContentLength, len(r.TransferEncoding) > 0
	return r, e, nil
}

func readEvidenceResponse(b *bufio.Reader, request *http.Request) (*http.Response, messageEvidence, error) {
	e, header, err := readEvidenceHead(b)
	if err != nil {
		return nil, e, err
	}
	qualifyFraming(&e, header)
	var wire bytes.Buffer
	wire.Write(e.line)
	for _, field := range e.headers {
		if !e.unsafe {
			wire.Write(field.Raw)
		}
	}
	wire.WriteString("\r\n")
	tail := &replayBodyReader{Reader: b}
	r, err := http.ReadResponse(bufio.NewReader(io.MultiReader(&wire, tail)), request)
	if err != nil {
		return nil, e, err
	}
	r.Header = header
	if e.unsafe {
		r.Body = http.NoBody
		r.ContentLength = -1
	}
	tail.remaining, tail.chunked = r.ContentLength, len(r.TransferEncoding) > 0
	return r, e, nil
}

func evidenceQuery(raw string) (url.Values, error) {
	values := url.Values{}
	var first error
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		k, e1 := url.QueryUnescape(key)
		v, e2 := url.QueryUnescape(value)
		if e1 != nil || e2 != nil {
			if first == nil {
				first = fmt.Errorf("invalid query escape")
			}
			continue
		}
		values.Add(k, v)
	}
	return values, first
}

func parseEvidenceForm(r *http.Request, body []byte) error {
	var queryErr error
	r.Form, queryErr = evidenceQuery(r.URL.RawQuery)
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") && contentType == "application/x-www-form-urlencoded" {
		post, err := evidenceQuery(string(body))
		r.PostForm = post
		for key, values := range post {
			r.Form[key] = append(append([]string(nil), values...), r.Form[key]...)
		}
		if err != nil {
			return err
		}
		return queryErr
	}
	return queryErr
}
