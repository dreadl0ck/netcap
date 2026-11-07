package apipolicy

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type parameter struct {
	name, location, kind string
	required             bool
	schema               *validator
}
type bodyPolicy struct {
	required bool
	content  map[string]*validator
}
type responsePolicy struct {
	headers []parameter
	body    bodyPolicy
}
type credential struct{ name, location, kind string }

// Operation is an immutable route-independent validation binding. A router can
// resolve its own destination and use the same request/response gates.
type Operation struct {
	method, path string
	parameters   []parameter
	body         bodyPolicy
	responses    map[string]responsePolicy
	security     [][]credential
	static       int
}

func object(x any) map[string]any { m, _ := x.(map[string]any); return m }
func text(x any) string           { s, _ := x.(string); return s }
func keys(m map[string]any, allowed string) bool {
	for k := range m {
		if !strings.HasPrefix(k, "x-") && !strings.Contains(" "+allowed+" ", " "+k+" ") {
			return false
		}
	}
	return true
}

// compileOpenAPI supports the bounded JSON OpenAPI 3.0.x/3.1.x profile. Features
// that affect validation but are not implemented fail closed at bootstrap.
func (b *Bundle) compileOpenAPI(v any) error {
	doc := object(v)
	version := text(doc["openapi"])
	if !regexp.MustCompile(`^3\.[01]\.[0-9]{1,3}$`).MatchString(version) || !keys(doc, "openapi info servers paths components security tags externalDocs jsonSchemaDialect") {
		return ErrInvalid
	}
	info := object(doc["info"])
	if text(info["title"]) == "" || text(info["version"]) == "" {
		return ErrInvalid
	}
	if dialect, ok := doc["jsonSchemaDialect"]; ok && dialect != "https://json-schema.org/draft/2020-12/schema" {
		return ErrInvalid
	}
	oas30 := strings.HasPrefix(version, "3.0.")
	paths := object(doc["paths"])
	if len(paths) == 0 || len(paths) > 128 {
		return ErrInvalid
	}
	schemes, err := securitySchemes(object(object(doc["components"])["securitySchemes"]))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for path, item := range paths {
		if !canonicalPath(path) {
			return ErrInvalid
		}
		pi := object(item)
		if pi == nil || !keys(pi, "summary description servers parameters get put post delete options head patch trace") {
			return ErrInvalid
		}
		shape := []string{}
		names := map[string]bool{}
		static := 0
		for _, segment := range strings.Split(path, "/") {
			if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2 {
				name := segment[1 : len(segment)-1]
				if names[name] || strings.ContainsAny(name, "{}") {
					return ErrInvalid
				}
				names[name] = true
				shape = append(shape, "{}")
			} else {
				if strings.ContainsAny(segment, "{}") {
					return ErrInvalid
				}
				shape = append(shape, segment)
				static++
			}
		}
		for method, raw := range pi {
			if !strings.Contains(" get put post delete options head patch trace ", " "+method+" ") {
				continue
			}
			o := object(raw)
			if o == nil || !keys(o, "tags summary description externalDocs operationId parameters requestBody responses callbacks deprecated security servers") {
				return ErrInvalid
			}
			if _, ok := o["callbacks"]; ok {
				return ErrInvalid
			}
			key := method + strings.Join(shape, "/")
			if seen[key] {
				return ErrInvalid
			}
			seen[key] = true
			op := &Operation{method: strings.ToUpper(method), path: path, static: static, responses: map[string]responsePolicy{}}
			params := map[string]parameter{}
			for _, source := range []any{pi["parameters"], o["parameters"]} {
				if source == nil {
					continue
				}
				a, ok := source.([]any)
				if !ok || len(a) > 64 {
					return ErrInvalid
				}
				level := map[string]bool{}
				for _, p := range a {
					param, err := compileParameter(object(p), oas30, "")
					if err != nil {
						return err
					}
					id := param.location + ":" + param.name
					if level[id] {
						return ErrInvalid
					}
					level[id] = true
					params[id] = param
				}
			}
			for _, p := range params {
				op.parameters = append(op.parameters, p)
			}
			for _, segment := range strings.Split(path, "/") {
				if strings.HasPrefix(segment, "{") {
					name := segment[1 : len(segment)-1]
					p, ok := params["path:"+name]
					if !ok || !p.required {
						return ErrInvalid
					}
				}
			}
			for _, p := range op.parameters {
				if p.location == "path" && !strings.Contains(path, "{"+p.name+"}") {
					return ErrInvalid
				}
			}
			if rb, exists := o["requestBody"]; exists {
				op.body, err = compileBody(object(rb), oas30)
				if err != nil {
					return err
				}
			}
			sec := doc["security"]
			if s, ok := o["security"]; ok {
				sec = s
			}
			op.security, err = compileSecurity(sec, schemes)
			if err != nil {
				return err
			}
			responses := object(o["responses"])
			if len(responses) == 0 {
				return ErrInvalid
			}
			for status, raw := range responses {
				if status != "default" {
					n, e := strconv.Atoi(status)
					if e != nil || n < 100 || n > 599 {
						return ErrInvalid
					}
				}
				r := object(raw)
				if r == nil || !keys(r, "description headers content links") {
					return ErrInvalid
				}
				if _, ok := r["description"].(string); !ok {
					return ErrInvalid
				}
				rp := responsePolicy{}
				for name, h := range object(r["headers"]) {
					hm := object(h)
					p, e := compileParameter(hm, oas30, name)
					if e != nil {
						return e
					}
					rp.headers = append(rp.headers, p)
				}
				if content, ok := r["content"]; ok {
					rp.body, err = compileBody(map[string]any{"content": content}, oas30)
					if err != nil {
						return err
					}
					rp.body.required = true
				}
				op.responses[status] = rp
			}
			b.operations = append(b.operations, op)
			if len(b.operations) > 256 {
				return ErrInvalid
			}
		}
	}
	for i, a := range b.operations {
		for _, c := range b.operations[:i] {
			if a.method != c.method || a.static != c.static {
				continue
			}
			x, y := strings.Split(a.path, "/"), strings.Split(c.path, "/")
			if len(x) != len(y) {
				continue
			}
			overlap := true
			for j := range x {
				if !strings.HasPrefix(x[j], "{") && !strings.HasPrefix(y[j], "{") && x[j] != y[j] {
					overlap = false
				}
			}
			if overlap {
				return ErrInvalid
			}
		}
	}
	sort.Slice(b.operations, func(i, j int) bool {
		if b.operations[i].static != b.operations[j].static {
			return b.operations[i].static > b.operations[j].static
		}
		return b.operations[i].path < b.operations[j].path
	})
	return nil
}

func compileParameter(m map[string]any, oas30 bool, header string) (parameter, error) {
	p := parameter{}
	if m == nil || !keys(m, "name in description required deprecated allowEmptyValue style explode allowReserved schema example examples") {
		return p, ErrInvalid
	}
	p.name = text(m["name"])
	p.location = text(m["in"])
	if header != "" {
		p.name = header
		p.location = "header"
	}
	if p.name == "" || strings.ContainsAny(p.name, "\r\n: ") || !strings.Contains(" path query header cookie ", " "+p.location+" ") {
		return p, ErrInvalid
	}
	if p.location == "header" {
		p.name = http.CanonicalHeaderKey(p.name)
	}
	if r, ok := m["required"]; ok {
		v, ok := r.(bool)
		if !ok {
			return p, ErrInvalid
		}
		p.required = v
	}
	if p.location == "path" && !p.required {
		return p, ErrInvalid
	}
	style := "form"
	if p.location == "path" || p.location == "header" {
		style = "simple"
	}
	if s, ok := m["style"]; ok && s != style {
		return p, ErrInvalid
	}
	if m["allowReserved"] == true || m["allowEmptyValue"] == true {
		return p, ErrInvalid
	}
	schema := object(m["schema"])
	p.kind = text(schema["type"])
	if !strings.Contains(" string boolean integer number ", " "+p.kind+" ") {
		return p, ErrInvalid
	}
	var err error
	p.schema, err = compileSchema(schema, oas30)
	return p, err
}

func compileBody(m map[string]any, oas30 bool) (bodyPolicy, error) {
	b := bodyPolicy{content: map[string]*validator{}}
	if m == nil || !keys(m, "description required content") {
		return b, ErrInvalid
	}
	if r, ok := m["required"]; ok {
		v, ok := r.(bool)
		if !ok {
			return b, ErrInvalid
		}
		b.required = v
	}
	content := object(m["content"])
	if len(content) == 0 || len(content) > 8 {
		return b, ErrInvalid
	}
	for media, raw := range content {
		if media != "application/json" && media != "multipart/form-data" && !(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json") && !strings.Contains(media, "*")) {
			return b, ErrInvalid
		}
		m := object(raw)
		if m == nil || !keys(m, "schema example examples") {
			return b, ErrInvalid
		}
		if media == "multipart/form-data" {
			s := object(m["schema"])
			if text(s["type"]) != "object" || !keys(s, "type properties required additionalProperties minProperties maxProperties description title") || s["additionalProperties"] != false {
				return b, ErrInvalid
			}
			for _, raw := range object(s["properties"]) {
				if text(object(raw)["type"]) != "string" || object(raw)["format"] != nil {
					return b, ErrInvalid
				}
			}
		}
		v, err := compileSchema(m["schema"], oas30)
		if err != nil {
			return b, err
		}
		b.content[media] = v
	}
	return b, nil
}

func securitySchemes(m map[string]any) (map[string]credential, error) {
	out := map[string]credential{}
	for name, raw := range m {
		s := object(raw)
		c := credential{kind: text(s["type"])}
		switch c.kind {
		case "apiKey":
			c.name = text(s["name"])
			c.location = text(s["in"])
			if c.name == "" || !strings.Contains(" header query cookie ", " "+c.location+" ") {
				return nil, ErrInvalid
			}
		case "http":
			c.location = "header"
			c.name = "Authorization"
			c.kind = strings.ToLower(text(s["scheme"]))
			if c.kind != "basic" && c.kind != "bearer" {
				return nil, ErrInvalid
			}
		case "oauth2", "openIdConnect":
			c.location = "header"
			c.name = "Authorization"
			c.kind = "bearer"
		default:
			return nil, ErrInvalid
		}
		out[name] = c
	}
	return out, nil
}

// Security requirements check credential presence/shape only. Scope membership,
// signatures, identity and authorization remain the application's responsibility.
func compileSecurity(raw any, schemes map[string]credential) ([][]credential, error) {
	if raw == nil {
		return nil, nil
	}
	a, ok := raw.([]any)
	if !ok || len(a) > 16 {
		return nil, ErrInvalid
	}
	out := [][]credential{}
	for _, r := range a {
		m := object(r)
		if m == nil {
			return nil, ErrInvalid
		}
		group := []credential{}
		for name, scopes := range m {
			c, ok := schemes[name]
			if !ok {
				return nil, ErrInvalid
			}
			ss, ok := scopes.([]any)
			if !ok {
				return nil, ErrInvalid
			}
			for _, s := range ss {
				if _, ok := s.(string); !ok {
					return nil, ErrInvalid
				}
			}
			if (c.kind == "apiKey" || c.kind == "basic") && len(ss) > 0 {
				return nil, ErrInvalid
			}
			group = append(group, c)
		}
		out = append(out, group)
	}
	return out, nil
}

// Resolve requires either a declared operation or an explicit exact passthrough.
// A nil operation with nil error is an intentional passthrough, never a fallback.
func (b *Bundle) Resolve(method, path string) (*Operation, error) {
	if !canonicalPath(path) {
		return nil, ErrInvalid
	}
	matched := ""
	for _, op := range b.operations {
		if _, ok := op.match(path); ok {
			if matched == "" {
				matched = op.path
			}
			if op.path == matched && op.method == method {
				return op, nil
			}
		}
	}
	if b.passthrough[Binding{Method: method, Path: path}] {
		return nil, nil
	}
	return nil, ErrInvalid
}

func (b *Bundle) Passthrough(method, path string) bool {
	return canonicalPath(path) && b.passthrough[Binding{Method: method, Path: path}]
}

func (o *Operation) match(path string) (map[string]string, bool) {
	a, c := strings.Split(o.path, "/"), strings.Split(path, "/")
	if len(a) != len(c) {
		return nil, false
	}
	params := map[string]string{}
	for i, s := range a {
		if strings.HasPrefix(s, "{") {
			if c[i] == "" {
				return nil, false
			}
			name := s[1 : len(s)-1]
			if _, ok := params[name]; ok {
				return nil, false
			}
			params[name] = c[i]
		} else if s != c[i] {
			return nil, false
		}
	}
	return params, true
}

func cookies(h http.Header) (url.Values, error) {
	v := url.Values{}
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || name == "" {
				return nil, ErrInvalid
			}
			v[name] = append(v[name], val)
		}
	}
	return v, nil
}

func (o *Operation) ValidateRequest(r *http.Request, body io.Reader) error {
	paths, ok := o.match(r.URL.Path)
	if !ok || !canonicalPath(r.URL.Path) || r.Method != o.method || strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") || len(r.Header.Values("Content-Type")) > 1 {
		return ErrInvalid
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return ErrInvalid
	}
	cookie, err := cookies(r.Header)
	if err != nil {
		return err
	}
	locations := map[string]url.Values{"query": query, "cookie": cookie, "header": url.Values(r.Header), "path": {}}
	for k, v := range paths {
		locations["path"][k] = []string{v}
	}
	for _, vals := range []url.Values{query, cookie} {
		for _, v := range vals {
			if len(v) != 1 {
				return ErrInvalid
			}
		}
	}
	allowed := map[string]bool{}
	for _, p := range o.parameters {
		if err := p.check(locations[p.location][p.name]); err != nil {
			return err
		}
		if p.location == "query" {
			allowed[p.name] = true
		}
	}
	securityOK := len(o.security) == 0
	for _, group := range o.security {
		valid := true
		for _, c := range group {
			name := c.name
			if c.location == "header" {
				name = http.CanonicalHeaderKey(name)
			}
			values := locations[c.location][name]
			if c.location == "query" {
				allowed[name] = true
			}
			if len(values) != 1 || values[0] == "" {
				valid = false
				continue
			}
			if c.kind == "basic" || c.kind == "bearer" {
				prefix, token, ok := strings.Cut(values[0], " ")
				if !ok || !strings.EqualFold(prefix, c.kind) || token == "" || strings.ContainsAny(token, " \t\r\n") {
					valid = false
				}
			}
		}
		if valid {
			securityOK = true
		}
	}
	if !securityOK {
		return ErrInvalid
	}
	for name := range query {
		if !allowed[name] {
			return ErrInvalid
		}
	}
	return o.body.check(r.Header.Get("Content-Type"), body)
}

func (p parameter) check(values []string) error {
	if len(values) == 0 {
		if p.required {
			return ErrInvalid
		}
		return nil
	}
	if len(values) != 1 {
		return ErrInvalid
	}
	var x any = values[0]
	switch p.kind {
	case "boolean":
		if values[0] != "true" && values[0] != "false" {
			return ErrInvalid
		}
		x = values[0] == "true"
	case "number", "integer":
		v, err := ParseJSON([]byte(values[0]))
		if err != nil {
			return err
		}
		if _, ok := v.(json.Number); !ok {
			return ErrInvalid
		}
		x = v
	}
	data, err := json.Marshal(x)
	if err != nil {
		return ErrInvalid
	}
	return p.schema.check(data)
}

func (b bodyPolicy) check(contentType string, r io.Reader) error {
	if r == nil {
		r = bytes.NewReader(nil)
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(data) > MaxBytes {
		return ErrInvalid
	}
	if len(data) == 0 {
		if b.required {
			return ErrInvalid
		}
		return nil
	}
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ErrInvalid
	}
	v, ok := b.content[media]
	if !ok {
		return ErrInvalid
	}
	if media != "multipart/form-data" {
		for k, val := range params {
			if k != "charset" || !strings.EqualFold(val, "utf-8") {
				return ErrInvalid
			}
		}
		return v.check(data)
	}
	if len(params) != 1 || params["boundary"] == "" {
		return ErrInvalid
	}
	mr := multipart.NewReader(bytes.NewReader(data), params["boundary"])
	fields := map[string]any{}
	for n := 0; ; n++ {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil || n >= 64 {
			return ErrInvalid
		}
		name := p.FormName()
		if name == "" || p.FileName() != "" || len(p.Header) > 2 || len(p.Header.Values("Content-Disposition")) != 1 {
			return ErrInvalid
		}
		for k := range p.Header {
			if k != "Content-Type" && k != "Content-Disposition" {
				return ErrInvalid
			}
		}
		if ct := p.Header.Get("Content-Type"); ct != "" && ct != "text/plain" {
			return ErrInvalid
		}
		if _, exists := fields[name]; exists {
			return ErrInvalid
		}
		part, err := io.ReadAll(io.LimitReader(p, 65537))
		if err != nil || len(part) > 65536 || !utf8.Valid(part) {
			return ErrInvalid
		}
		fields[name] = string(part)
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return ErrInvalid
	}
	return v.check(encoded)
}

// ValidateResponse runs only when the caller explicitly enables its delivery
// gate. The origin has already executed; no response gate is a transaction undo.
func (o *Operation) ValidateResponse(status int, headers http.Header, body io.Reader) error {
	if len(headers.Values("Content-Type")) > 1 {
		return ErrInvalid
	}
	r, ok := o.responses[strconv.Itoa(status)]
	if !ok {
		r, ok = o.responses["default"]
	}
	if !ok {
		return ErrInvalid
	}
	for _, p := range r.headers {
		if err := p.check(headers.Values(p.name)); err != nil {
			return err
		}
	}
	return r.body.check(headers.Get("Content-Type"), body)
}
