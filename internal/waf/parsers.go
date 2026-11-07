package waf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

const maxArguments = 1000
const maxJSONDepth = 64

func argumentCount(raw string) int {
	if raw == "" {
		return 0
	}
	return strings.Count(raw, "&") + 1
}

// Structural failures are independent of disruptive rules and monitor mode.
// In particular, an early Coraza interruption must not skip malformed-body rejection.
func validatePayload(r *http.Request, body []byte) error {
	return validatePayloadReader(r, bytes.NewReader(body), int64(len(body)))
}

func validatePayloadReader(r *http.Request, body io.Reader, size int64) error {
	queryCount := argumentCount(r.URL.RawQuery)
	if queryCount > maxArguments {
		return rejection{413}
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return nil
	}
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return rejection{400}
	}
	if size == 0 {
		return nil
	}
	switch {
	case media == "application/json" || strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json"):
		// encoding/json materializes scalar tokens. Bound those allocations explicitly.
		if size > NativeBodyBytes {
			return rejection{413}
		}
		d := json.NewDecoder(body)
		d.UseNumber()
		budget := maxArguments - queryCount
		if err := validateJSONValue(d, 0, &budget); err != nil {
			return err
		}
		if _, err := d.Token(); err != io.EOF {
			return rejection{400}
		}
	case media == "application/x-www-form-urlencoded":
		if size > NativeBodyBytes {
			return rejection{413}
		}
		data, err := io.ReadAll(body)
		if err != nil {
			return rejection{400}
		}
		if queryCount+argumentCount(string(data)) > maxArguments {
			return rejection{413}
		}
		if !validQuery(string(data)) {
			return rejection{400}
		}
	case media == "application/xml" || media == "text/xml" || strings.HasSuffix(media, "+xml"):
		if size > NativeBodyBytes {
			return rejection{413}
		}
		d := xml.NewDecoder(body)
		depth, roots, nodes := 0, 0, 0
		for {
			token, err := d.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return rejection{400}
			}
			switch token := token.(type) {
			case xml.StartElement:
				if depth == 0 {
					roots++
				}
				depth++
				nodes += 1 + len(token.Attr)
				if roots > 1 || depth > maxJSONDepth {
					return rejection{400}
				}
				if nodes+queryCount > maxArguments {
					return rejection{413}
				}
			case xml.EndElement:
				depth--
			case xml.CharData:
				if depth == 0 && strings.TrimSpace(string(token)) != "" {
					return rejection{400}
				}
			}
		}
		if depth != 0 || roots != 1 {
			return rejection{400}
		}
	case media == "multipart/form-data":
		boundary := params["boundary"]
		if len(boundary) == 0 || len(boundary) > 70 {
			return rejection{400}
		}
		m := multipart.NewReader(body, boundary)
		for count := queryCount; ; count++ {
			part, err := m.NextRawPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return rejection{400}
			}
			if count >= maxArguments {
				return rejection{413}
			}
			if len(part.Header.Values("Content-Disposition")) != 1 {
				return rejection{400}
			}
			disposition, fields, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			if err != nil || disposition != "form-data" || fields["name"] == "" {
				return rejection{400}
			}
			if _, err := io.Copy(io.Discard, part); err != nil {
				return rejection{400}
			}
			if err := part.Close(); err != nil {
				return rejection{400}
			}
		}
	}
	return nil
}

func validateJSONValue(d *json.Decoder, depth int, budget *int) error {
	if depth > maxJSONDepth {
		return rejection{400}
	}
	t, err := d.Token()
	if err != nil {
		return rejection{400}
	}
	if delim, ok := t.(json.Delim); ok {
		if delim != '{' && delim != '[' {
			return rejection{400}
		}
		for d.More() {
			*budget--
			if *budget < 0 {
				return rejection{413}
			}
			if delim == '{' {
				if _, err := d.Token(); err != nil {
					return rejection{400}
				}
			}
			if err := validateJSONValue(d, depth+1, budget); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return rejection{400}
		}
	}
	return nil
}
