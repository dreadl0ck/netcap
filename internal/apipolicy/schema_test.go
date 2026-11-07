package apipolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func parsed(t *testing.T, s string) any {
	t.Helper()
	v, err := ParseJSON([]byte(s))
	if err != nil {
		var raw any
		t.Fatalf("parse: %v JSON syntax: %v", err, json.Unmarshal([]byte(s), &raw))
	}
	return v
}

func TestMultipartRestrictionsAndSchemas(t *testing.T) {
	b := &Bundle{}
	if err := b.compileOpenAPI(parsed(t, contract)); err != nil {
		t.Fatal(err)
	}
	op, err := b.Resolve("POST", "/items/3")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                     string
		duplicate, file, missing bool
		want                     bool
	}{
		{name: "valid", want: true}, {name: "duplicate", duplicate: true}, {name: "file", file: true}, {name: "missing", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			writer := multipart.NewWriter(&data)
			if !tc.missing {
				if tc.file {
					p, e := writer.CreateFormFile("text", "file.txt")
					if e != nil {
						t.Fatal(e)
					}
					_, _ = p.Write([]byte("x"))
				} else {
					if e := writer.WriteField("text", "SQL SELECT 'benign'"); e != nil {
						t.Fatal(e)
					}
				}
			}
			if tc.duplicate {
				if e := writer.WriteField("text", "duplicate"); e != nil {
					t.Fatal(e)
				}
			}
			if e := writer.Close(); e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest("POST", "/items/3?limit=2", nil)
			r.Header.Set("Content-Type", writer.FormDataContentType())
			r.Header.Set("X-Key", "x")
			r.Header.Set("X-Trace", "x")
			if got := op.ValidateRequest(r, &data) == nil; got != tc.want {
				t.Fatalf("multipart got %v want %v", got, tc.want)
			}
		})
	}
	var data bytes.Buffer
	w := multipart.NewWriter(&data)
	p, err := w.CreatePart(textproto.MIMEHeader{"Content-Disposition": {`form-data; name="text"`}, "Content-Transfer-Encoding": {"base64"}})
	if err != nil {
		t.Fatal(err)
	}
	p.Write([]byte("YWJj"))
	w.Close()
	r := httptest.NewRequest("POST", "/items/3?limit=2", nil)
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.Header.Set("X-Key", "x")
	r.Header.Set("X-Trace", "x")
	if op.ValidateRequest(r, &data) == nil {
		t.Fatal("multipart transfer coding bypass")
	}
}

func TestUnsupportedOpenAPIContractsFailBootstrap(t *testing.T) {
	for _, transform := range []func(map[string]any){
		func(m map[string]any) { m["openapi"] = "3.1.nope" },
		func(m map[string]any) { delete(m, "info") },
		func(m map[string]any) { object(object(m["paths"])["/items/{id}"])["$ref"] = "https://example.com" },
		func(m map[string]any) {
			object(object(object(m["paths"])["/items/{id}"])["post"])["callbacks"] = map[string]any{}
		},
		func(m map[string]any) {
			params := object(object(object(m["paths"])["/items/{id}"])["post"])["parameters"].([]any)
			object(params[0])["style"] = "deepObject"
		},
		func(m map[string]any) {
			paths := object(m["paths"])
			paths["/{other}/items"] = paths["/items/{id}"]
			object(paths["/{other}/items"])["parameters"] = []any{map[string]any{"name": "other", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}}
		},
	} {
		doc := parsed(t, contract).(map[string]any)
		transform(doc)
		if (&Bundle{}).compileOpenAPI(doc) == nil {
			t.Fatal("unsupported contract silently accepted")
		}
	}
}

func TestActualJSONSchema(t *testing.T) {
	v, err := compileSchema(parsed(t, `{"type":"object","required":["n","nested"],"additionalProperties":false,"properties":{"n":{"type":"integer","minimum":9007199254740993,"maximum":9007199254740993},"nested":{"oneOf":[{"type":"null"},{"type":"array","minItems":1,"items":{"type":"string","pattern":"^[a-z]+$"}}]}}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`{"n":9007199254740993,"nested":null}`, `{"n":9007199254740993,"nested":["abc"]}`} {
		if err := v.check([]byte(s)); err != nil {
			t.Fatalf("valid %s: %v", s, err)
		}
	}
	for _, s := range []string{`{"n":9007199254740992,"nested":null}`, `{"n":9007199254740993}`, `{"n":null,"nested":null}`, `{"n":9007199254740993,"nested":[]}`, `{"n":9007199254740993,"nested":["123"]}`, `{"n":9007199254740993,"nested":null,"extra":1}`, `{"n":9007199254740993,"n":9007199254740993,"nested":null}`} {
		if v.check([]byte(s)) == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}

func TestJSONAndSchemaBudgets(t *testing.T) {
	for _, s := range []string{`{"x":1,"\u0078":2}`, `{"x":{"a":1,"a":2}}`, `1e999999999`, `1e-99999999`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), "[" + strings.Repeat("0,", 1024) + "0]", `{} {}`} {
		if _, err := ParseJSON([]byte(s)); err == nil {
			t.Fatalf("accepted %.60s", s)
		}
	}
	for _, s := range []string{`{"$dynamicRef":"#x"}`, `{"format":"email"}`, `{"pattern":"(?=bad)"}`, `{"unknownAssertion":true}`, `{"minimum":"1"}`, `{"multipleOf":0}`, `{"type":"potato"}`, `{"pattern":"` + strings.Repeat("x", 257) + `"}`} {
		if _, err := compileSchema(parsed(t, s), false); err == nil {
			t.Fatalf("accepted schema %s", s)
		}
	}
	v, err := compileSchema(parsed(t, `{"type":"object","properties":{"x":{"type":"string","nullable":true}},"required":["x"]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if v.check([]byte(`{"x":null}`)) != nil || v.check([]byte(`{}`)) == nil {
		t.Fatal("OAS nullable changed required semantics")
	}
	var deep any = true
	for i := 0; i < 18; i++ {
		deep = map[string]any{"items": deep}
	}
	if _, err := compileSchema(deep, false); err == nil {
		t.Fatal("schema depth budget bypass")
	}
	properties := map[string]any{}
	for i := 0; i < 513; i++ {
		properties[strings.Repeat("x", i+1)] = true
	}
	if _, err := compileSchema(map[string]any{"properties": properties}, false); err == nil {
		t.Fatal("schema node budget bypass")
	}
	v, err = compileSchema(parsed(t, `{"type":"array","items":{"type":"string"}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(strings.Split(strings.Repeat(strings.Repeat("x", 1024)+",", 128), ","))
	if v.check(data) == nil {
		t.Fatal("evaluation product budget bypass")
	}
}

func TestOpenAPIPathPrecedenceAndMethodBoundary(t *testing.T) {
	b := &Bundle{}
	doc := parsed(t, `{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":{"/items/special":{"get":{"responses":{"204":{"description":"empty"}}}},"/items/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"post":{"responses":{"204":{"description":"empty"}}}}}}`)
	if err := b.compileOpenAPI(doc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path string }{
		{"POST", "/items/special"}, {"DELETE", "/items/normal"}, {"GET", "/unknown"},
		{"POST", "/items/.."}, {"POST", "/items/%2e"}, {"POST", "/items/\\"}, {"POST", "/items//"},
	} {
		if _, err := b.Resolve(tc.method, tc.path); err == nil {
			t.Fatalf("accepted %s %s", tc.method, tc.path)
		}
	}
	if _, err := b.Resolve("POST", "/items/normal"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Resolve("GET", "/items/special"); err != nil {
		t.Fatal(err)
	}
}

func TestLocalReferencesBounded(t *testing.T) {
	docs := map[string]any{"a": parsed(t, `{"$defs":{"value":{"type":"integer","minimum":2}}}`), "cycle": parsed(t, `{"$ref":"cycle"}`)}
	for _, s := range []string{`{"$ref":"http://127.0.0.1/private"}`, `{"$ref":"../a"}`, `{"$ref":"/etc/passwd"}`, `{"$ref":"file:///etc/passwd"}`, `{"$ref":"cycle"}`, `{"$ref":"a#/$defs/missing"}`, `{"$ref":"a#/$defs/value","minimum":3}`} {
		n := 1024
		if _, err := expand(parsed(t, s), "a", docs, map[string]bool{}, 0, &n); err == nil {
			t.Fatalf("accepted ref %s", s)
		}
	}
	n := 1024
	x, err := expand(parsed(t, `{"$ref":"a#/$defs/value"}`), "a", docs, map[string]bool{}, 0, &n)
	if err != nil {
		t.Fatal(err)
	}
	v, err := compileSchema(x, false)
	if err != nil || v.check([]byte(`1`)) == nil || v.check([]byte(`2`)) != nil {
		t.Fatal("declared schema ref not enforced", err)
	}
	docs["bomb"] = parsed(t, `{"a":{"$ref":"a#/$defs/value"},"b":{"$ref":"a#/$defs/value"}}`)
	n = 2
	if _, err := expand(docs["bomb"], "bomb", docs, map[string]bool{}, 0, &n); err == nil {
		t.Fatal("expansion budget bypass")
	}
	n = 1024
	x, err = expand(parsed(t, `{"const":{"$ref":"literal-instance-value"}}`), "a", docs, map[string]bool{}, 0, &n)
	if err != nil {
		t.Fatal(err)
	}
	v, err = compileSchema(x, false)
	if err != nil || v.check([]byte(`{"$ref":"literal-instance-value"}`)) != nil || v.check([]byte(`{}`)) == nil {
		t.Fatal("const data treated as schema reference", err)
	}
}

func TestBootstrapRefsNeverUseNetwork(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`true`)) }))
	defer server.Close()
	for _, ref := range []string{server.URL + "/schema", "api.json#/components/schemas/Cycle"} {
		dir := t.TempDir()
		doc := object(parsed(t, contract))
		doc["components"] = map[string]any{"schemas": map[string]any{"Cycle": map[string]any{"$ref": ref}}}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "api.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		decl := Declaration{Version: "netcap-api/v1", OpenAPI: "api.json", Artifacts: map[string]Artifact{"api.json": {Path: "api.json", SHA256: digest(data)}}}
		manifest, err := json.Marshal(decl)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bundle.json"), manifest, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, "bundle.json", digest(manifest)); err == nil {
			t.Fatal("remote/cyclic ref accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("bootstrap attempted %d network requests", calls.Load())
	}
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestPinnedOpenAPIReferenceSnapshot(t *testing.T) {
	dir := t.TempDir()
	api := []byte(strings.Replace(contract, `"text":{"type":"string"}`, `"text":{"$ref":"text.json"}`, 1))
	artifacts := map[string][]byte{"api.json": api, "text.json": []byte(`{"type":"string","minLength":2}`)}
	d := Declaration{Version: "netcap-api/v1", OpenAPI: "api.json", Artifacts: map[string]Artifact{}}
	for name, data := range artifacts {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		d.Artifacts[name] = Artifact{Path: name, SHA256: digest(data)}
	}
	manifest, _ := json.Marshal(d)
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir, "bundle.json", digest(manifest))
	if err != nil {
		t.Fatal(err)
	}
	op, err := b.Resolve("POST", "/items/3")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/items/3?limit=2", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Key", "shape-only")
	r.Header.Set("X-Trace", "trace")
	if op.ValidateRequest(r, strings.NewReader(`{"text":"x"}`)) == nil || op.ValidateRequest(r, strings.NewReader(`{"text":"ok"}`)) != nil {
		t.Fatal("pinned reference assertion ignored")
	}
	if err := os.WriteFile(filepath.Join(dir, "text.json"), []byte(`{"type":"integer"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "bundle.json", digest(manifest)); err == nil {
		t.Fatal("changed referenced artifact bypassed digest pin")
	}
	if op.ValidateRequest(r, strings.NewReader(`{"text":"ok"}`)) != nil {
		t.Fatal("bootstrap snapshot changed after artifact replacement")
	}
	r.Header.Add("Content-Type", "application/json")
	if op.ValidateRequest(r, strings.NewReader(`{"text":"ok"}`)) == nil {
		t.Fatal("duplicate content type accepted by module hook")
	}
}

func TestPinnedBootstrapConfinement(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	manifest := []byte(`{"version":"netcap-api/v1","passthrough":[{"method":"GET","path":"/health"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir, "bundle.json", digest(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if op, err := b.Resolve("GET", "/health"); op != nil || err != nil {
		t.Fatal("explicit passthrough")
	}
	if _, err := b.Resolve("GET", "/unknown"); err == nil {
		t.Fatal("silent fallback")
	}
	if _, err := Load(dir, "bundle.json", strings.Repeat("0", 64)); err == nil {
		t.Fatal("digest pin ignored")
	}
	if err := os.WriteFile(filepath.Join(outside, "bundle.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "bundle.json"), filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../bundle.json", "escape", filepath.Join(outside, "bundle.json")} {
		if _, err := Load(dir, path, digest(manifest)); err == nil {
			t.Fatalf("escaped root: %s", path)
		}
	}
	bad := Declaration{Version: "netcap-api/v1", Artifacts: map[string]Artifact{"remote": {Path: "https://example.com/schema", SHA256: digest(manifest)}}, Passthrough: []Binding{{Method: "GET", Path: "/health"}}}
	data, _ := json.Marshal(bad)
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "bad.json", digest(data)); err == nil {
		t.Fatal("remote artifact accepted")
	}
}

const contract = `{"openapi":"3.1.0","info":{"title":"test","version":"1"},"components":{"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-Key"}}},"security":[{"key":[]}],"paths":{"/items/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer","minimum":1}}],"post":{"parameters":[{"name":"limit","in":"query","required":true,"schema":{"type":"integer","minimum":1,"maximum":10}},{"name":"X-Trace","in":"header","required":true,"schema":{"type":"string","minLength":1}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["text"],"properties":{"text":{"type":"string"}},"additionalProperties":false}},"multipart/form-data":{"schema":{"type":"object","required":["text"],"properties":{"text":{"type":"string"}},"additionalProperties":false}}}},"responses":{"200":{"description":"OK","headers":{"X-Result":{"required":true,"schema":{"type":"integer","minimum":1}}},"content":{"application/json":{"schema":{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}}}}}}}}}`

func TestOpenAPIValidation(t *testing.T) {
	for _, version := range []string{"3.0.3", "3.1.0"} {
		t.Run(version, func(t *testing.T) {
			b := &Bundle{}
			fixture := strings.ReplaceAll(strings.ReplaceAll(contract, "3.1.0", version), `"const":true`, `"enum":[true]`)
			if err := b.compileOpenAPI(parsed(t, fixture)); err != nil {
				t.Fatal(err)
			}
			op, err := b.Resolve("POST", "/items/3")
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				path, body string
				want       bool
			}{
				{"/items/3?limit=2", `{"text":"select * from users; -- benign prose"}`, true},
				{"/items/3?limit=2", `{"text":null}`, false}, {"/items/3?limit=2", `{}`, false}, {"/items/3?limit=2", `{"text":"x","text":"y"}`, false},
				{"/items/0?limit=2", `{"text":"x"}`, false}, {"/items/3?limit=11", `{"text":"x"}`, false}, {"/items/3", `{"text":"x"}`, false},
				{"/items/3?limit=2&limit=2", `{"text":"x"}`, false}, {"/items/3?limit=2&unknown=1", `{"text":"x"}`, false},
			} {
				r := httptest.NewRequest("POST", tc.path, nil)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Key", "presence-is-not-authorization")
				r.Header.Set("X-Trace", "trace")
				if got := op.ValidateRequest(r, strings.NewReader(tc.body)) == nil; got != tc.want {
					t.Errorf("%s %s got %v", tc.path, tc.body, got)
				}
			}
			r := httptest.NewRequest("POST", "/items/3?limit=2", nil)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Trace", "trace")
			if op.ValidateRequest(r, strings.NewReader(`{"text":"x"}`)) == nil {
				t.Fatal("missing security credential accepted")
			}
			r.Header.Set("X-Key", "x")
			r.Header.Add("X-Trace", "other")
			if op.ValidateRequest(r, strings.NewReader(`{"text":"x"}`)) == nil {
				t.Fatal("duplicate header accepted")
			}
			h := r.Header.Clone()
			h.Set("X-Result", "1")
			if op.ValidateResponse(200, h, bytes.NewBufferString(`{"ok":true}`)) != nil {
				t.Fatal("valid response denied")
			}
			if op.ValidateResponse(200, h, bytes.NewBufferString(`{"ok":false}`)) == nil {
				t.Fatal("response schema ignored")
			}
		})
	}
}
