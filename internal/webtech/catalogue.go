// Package webtech recognizes advertised, transaction-scoped web technology.
// Descriptors select bounded parsers, never probes, regex programs or scripts.
package webtech

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	FileName     = "webtech-descriptors.json"
	MaxCatalogue = 64 << 10
	MaxPrefix    = 64 << 10
	MaxTag       = 4 << 10
	MaxAggregate = 16 << 20
)

type Rule struct {
	ID        string `json:"id"`
	Product   string `json:"product"`
	Selector  string `json:"selector"`
	Token     string `json:"token"`
	Precision string `json:"precision"`
	Method    string `json:"method"`
	Status    int    `json:"status"`
}
type Catalogue struct {
	Format        string `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}
type Engine struct{ catalogue Catalogue }

func (e *Engine) RuleCount() int { return len(e.catalogue.Rules) }

type Status struct {
	State  string `json:"state"`
	SHA256 string `json:"sha256"`
	Rules  int    `json:"rules"`
}

//go:embed webtech-descriptors.json
var descriptors []byte

func Parse(b []byte) (*Engine, error) {
	if len(b) > MaxCatalogue {
		return nil, errors.New("webtech catalogue exceeds 64 KiB")
	}
	// Token validation rejects duplicate keys, including nested descriptor fields.
	d := json.NewDecoder(bytes.NewReader(b))
	if err := unique(d, 0); err != nil {
		return nil, err
	}
	var c Catalogue
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	if c.Format != "netcap-webtech" || c.SchemaVersion != 1 || len(c.Rules) == 0 || len(c.Rules) > 4 {
		return nil, errors.New("unsupported webtech catalogue")
	}
	var allowed Catalogue
	_ = json.Unmarshal(descriptors, &allowed)
	seen := map[string]bool{}
	for _, r := range c.Rules {
		valid := false
		for _, a := range allowed.Rules {
			if r == a {
				valid = true
			}
		}
		if !valid || seen[r.ID] {
			return nil, fmt.Errorf("unreviewed or duplicate descriptor %q", r.ID)
		}
		seen[r.ID] = true
	}
	return &Engine{c}, nil
}
func unique(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("JSON depth")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return errors.New("duplicate key")
			}
			seen[s] = true
			if e = unique(d, depth+1); e != nil {
				return e
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err = unique(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}
func Builtin() *Engine {
	var c Catalogue
	_ = json.Unmarshal(descriptors, &c)
	c.Rules = c.Rules[:2]
	return &Engine{c}
}

func Root() string {
	if p := os.Getenv("NC_ENRICHMENT_ROOT"); p != "" {
		return p
	}
	p := os.Getenv("NC_CONFIG_ROOT")
	if p == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			p = filepath.Join("/usr", "local", "etc", "netcap")
		} else {
			p = filepath.Join(home, ".config", "netcap")
		}
	}
	return filepath.Join(p, "enrichment")
}
func Load(root string) (*Engine, Status) {
	fallback := func(state string) (*Engine, Status) { return Builtin(), Status{State: state, Rules: 2} }
	r, err := os.OpenRoot(root)
	if err != nil {
		return fallback("missing-builtins")
	}
	defer r.Close()
	st, err := r.Lstat(FileName)
	if err != nil {
		return fallback("missing-builtins")
	}
	if !st.Mode().IsRegular() || st.Size() > MaxCatalogue {
		return fallback("invalid-builtins")
	}
	f, err := openCatalogue(r)
	if err != nil {
		return fallback("invalid-builtins")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(st, after) {
		return fallback("invalid-builtins")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxCatalogue+1))
	if err != nil {
		return fallback("invalid-builtins")
	}
	e, err := Parse(b)
	if err != nil {
		return fallback("invalid-builtins")
	}
	return e, Status{State: "external", Rules: len(e.catalogue.Rules), SHA256: fmt.Sprintf("%x", sha256.Sum256(b))}
}
