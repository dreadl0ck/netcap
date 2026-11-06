// Package servicesignatures identifies passive service greetings using bounded
// protocol parsers. Rules select parsers; they never contain executable patterns.
package servicesignatures

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	Format            = "netcap-service-signatures"
	SchemaVersion     = 1
	FileName          = "service-signatures.json"
	MaxCatalogueBytes = 1 << 20
	MaxBannerBytes    = 8192
)

type Provenance struct {
	URL     string `json:"url"`
	Section string `json:"section"`
}

type Rule struct {
	ID         string       `json:"id"`
	Protocol   string       `json:"protocol"`
	Transport  string       `json:"transport"`
	Direction  string       `json:"direction"`
	Kind       string       `json:"kind"`
	Provenance []Provenance `json:"provenance"`
}

type Catalogue struct {
	Format        string `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

type Result struct {
	ID       string
	Protocol string
	Product  string
	Version  string
}

type Engine struct {
	catalogue    Catalogue
	sourceSHA256 string
}

//go:embed builtin.json
var builtin []byte

func Builtin() *Engine {
	e, err := Parse(bytes.NewReader(builtin))
	if err != nil {
		panic(err)
	}
	return e
}

// Load falls back to the independently authored protocol catalogue. The error
// must be surfaced to the operator; a bad external catalogue never stays active.
func Load(path string) (*Engine, error) {
	f, err := openCatalogue(path)
	if err != nil {
		return Builtin(), fmt.Errorf("service signatures degraded: using 4 built-in protocol rules: %w", err)
	}
	defer f.Close()
	e, err := Parse(f)
	if err != nil {
		return Builtin(), fmt.Errorf("service signatures degraded: invalid catalogue; using 4 built-in protocol rules: %w", err)
	}
	return e, nil
}

func openCatalogue(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > MaxCatalogueBytes {
		return nil, errors.New("signature source must be a regular file of at most 1 MiB")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, errors.New("signature source changed while opening")
	}
	return f, nil
}

func Parse(r io.Reader) (*Engine, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxCatalogueBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCatalogueBytes {
		return nil, errors.New("catalogue exceeds 1 MiB")
	}
	var c Catalogue
	if err := validateJSONValue(json.NewDecoder(bytes.NewReader(b)), 0); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing catalogue data")
	}
	if c.Format != Format || c.SchemaVersion != SchemaVersion || len(c.Rules) == 0 || len(c.Rules) > 64 {
		return nil, errors.New("unsupported or empty catalogue")
	}
	ids, kinds := map[string]bool{}, map[string]bool{}
	for _, rule := range c.Rules {
		protocol := map[string]string{"ssh-ident": "ssh", "http1-response": "http", "smtp-greeting": "smtp", "ftp-greeting": "ftp"}[rule.Kind]
		if protocol == "" || rule.Protocol != protocol || rule.Transport != "tcp" || rule.Direction != "server-to-client" || !validID(rule.ID) || ids[rule.ID] || kinds[rule.Kind] {
			return nil, fmt.Errorf("invalid or colliding rule %q", rule.ID)
		}
		if len(rule.Provenance) == 0 || len(rule.Provenance) > 8 {
			return nil, errors.New("missing or excessive provenance")
		}
		for _, p := range rule.Provenance {
			u, err := url.Parse(p.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(p.URL) > 2048 || strings.TrimSpace(p.Section) == "" || len(p.Section) > 256 {
				return nil, errors.New("invalid provenance")
			}
		}
		ids[rule.ID], kinds[rule.Kind] = true, true
	}
	return &Engine{catalogue: c, sourceSHA256: fmt.Sprintf("%x", sha256.Sum256(b))}, nil
}

// Reject duplicate keys consistently across runtimes, including provenance.
func validateJSONValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("catalogue nesting exceeds 16")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || name != strings.ToLower(name) || seen[name] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[name] = true
			if err := validateJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := validateJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func validID(s string) bool {
	if !strings.HasPrefix(s, "netcap.") || len(s) <= 7 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// Catalogue returns a copy so callers cannot mutate a live engine.
func (e *Engine) Catalogue() Catalogue {
	b, _ := json.Marshal(e.catalogue)
	var c Catalogue
	_ = json.Unmarshal(b, &c)
	return c
}

// Identify expects a contiguous prefix starting at the server's first byte.
// Call again with the accumulated prefix after segmentation; never concatenate gaps.
func (e *Engine) Identify(data []byte, transport, direction string) (Result, bool) {
	if e == nil || len(data) == 0 {
		return Result{}, false
	}
	if len(data) > MaxBannerBytes {
		data = data[:MaxBannerBytes]
	}
	end := bytes.Index(data, []byte("\r\n"))
	if end < 0 {
		return Result{}, false
	}
	line := string(data[:end])
	for _, c := range []byte(line) {
		if c < 32 || c > 126 {
			return Result{}, false
		}
	}
	for _, rule := range e.catalogue.Rules {
		if transport != rule.Transport || direction != rule.Direction {
			continue
		}
		product, version, ok := match(rule.Kind, line, end+2)
		if ok {
			return Result{ID: rule.ID, Protocol: rule.Protocol, Product: product, Version: version}, true
		}
	}
	return Result{}, false
}

func match(kind, line string, size int) (string, string, bool) {
	switch kind {
	case "ssh-ident":
		if size > 255 || !strings.HasPrefix(line, "SSH-2.0-") {
			break
		}
		software := strings.SplitN(strings.TrimPrefix(line, "SSH-2.0-"), " ", 2)[0]
		if software == "" {
			break
		}
		for _, c := range software {
			if c <= 32 || c > 126 || c == '-' {
				return "", "", false
			}
		}
		return software, "", true
	case "http1-response":
		if len(line) < 13 || !(strings.HasPrefix(line, "HTTP/1.0 ") || strings.HasPrefix(line, "HTTP/1.1 ")) || line[12] != ' ' {
			break
		}
		if line[9] >= '1' && line[9] <= '5' && digit(line[10]) && digit(line[11]) {
			return "", "", true
		}
	case "smtp-greeting", "ftp-greeting":
		// 220 alone is shared by SMTP and FTP and is deliberately insufficient.
		if len(line) < 5 || !strings.HasPrefix(line, "220 ") || size > 512 {
			break
		}
		words := strings.FieldsFunc(strings.ToUpper(line[4:]), func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') })
		smtp, ftp := false, false
		for _, w := range words {
			smtp = smtp || w == "SMTP" || w == "ESMTP"
			ftp = ftp || w == "FTP"
		}
		if kind == "smtp-greeting" && smtp && !ftp || kind == "ftp-greeting" && ftp && !smtp {
			return "", "", true
		}
	}
	return "", "", false
}

func digit(c byte) bool { return c >= '0' && c <= '9' }
