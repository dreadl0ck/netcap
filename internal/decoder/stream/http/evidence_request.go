package http

import (
	"bufio"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
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

type singleByteReader struct{ io.Reader }

func (r singleByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func readEvidenceRequest(b *bufio.Reader) (*http.Request, string, error) {
	prefix, _ := b.Peek(b.Size())
	end := strings.IndexByte(string(prefix), '\n')
	if end < 0 {
		return requestResult(http.ReadRequest(b))
	}
	line := strings.TrimSuffix(strings.TrimSuffix(string(prefix[:end+1]), "\n"), "\r")
	parts := strings.Split(line, " ")
	if len(parts) != 3 || escapeTargetControls(parts[1]) == parts[1] {
		return requestResult(http.ReadRequest(b))
	}
	_, err := b.Discard(end + 1)
	if err != nil {
		return nil, "", err
	}
	clean := parts[0] + " " + escapeTargetControls(parts[1]) + " " + parts[2] + "\r\n"
	// Do not read ahead into a later pipelined request through the temporary reader.
	r, err := http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader(clean), singleByteReader{b})))
	if err != nil {
		return nil, "", err
	}
	r.RequestURI = parts[1]
	return r, "invalid-request-target-control-byte", nil
}

func requestResult(r *http.Request, err error) (*http.Request, string, error) { return r, "", err }

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
