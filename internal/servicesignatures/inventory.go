package servicesignatures

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const InventoryFileName = "service-signatures-status.json"

type Inventory struct {
	Format        string     `json:"format"`
	SchemaVersion int        `json:"schema_version"`
	Scope         string     `json:"scope"`
	State         string     `json:"state"`
	Source        string     `json:"source"`
	SourceSHA256  string     `json:"source_sha256,omitempty"`
	CheckedAt     time.Time  `json:"checked_at"`
	Degraded      bool       `json:"degraded"`
	Warning       string     `json:"warning,omitempty"`
	RuleCount     int        `json:"rule_count"`
	Protocols     []string   `json:"protocols"`
	Catalogue     *Catalogue `json:"catalogue,omitempty"`
	Limitations   []string   `json:"limitations"`
}

func (e *Engine) Inventory(scope string, loadError error) Inventory {
	c := e.Catalogue()
	i := UnavailableInventory("loaded", "")
	i.Scope, i.Source, i.SourceSHA256 = scope, "external", e.sourceSHA256
	i.Catalogue, i.RuleCount = &c, len(c.Rules)
	i.Degraded = loadError != nil
	if loadError != nil {
		i.Source, i.Warning = "builtin", loadError.Error()
	}
	for _, r := range c.Rules {
		i.Protocols = append(i.Protocols, r.Protocol)
	}
	sort.Strings(i.Protocols)
	return i
}

func UnavailableInventory(state, warning string) Inventory {
	return Inventory{
		Format: "netcap-service-signature-inventory", SchemaVersion: 1, Scope: "capture", State: state,
		Source: "none", CheckedAt: time.Now().UTC(), Warning: warning, Protocols: []string{},
		Limitations: []string{"TCP server-to-client greetings only; no UDP or application-wide fingerprint coverage", "Complete contiguous CRLF first line required; capture gaps are not joined", "SMTP/FTP require distinct protocol tokens; generic or ambiguous 220 greetings are not identified", "Protocol provenance is source evidence, not a claim of human approval"},
	}
}

// WriteInventory atomically records the catalogue used by this capture, including
// a disabled decoder, so an older run's snapshot cannot masquerade as this run.
func WriteInventory(dir string, i Inventory) error {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".service-signatures-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, InventoryFileName))
}

func ReadInventory(path string) (Inventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return Inventory{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 2*MaxCatalogueBytes+1))
	if err != nil {
		return Inventory{}, err
	}
	if len(b) > 2*MaxCatalogueBytes {
		return Inventory{}, errors.New("signature inventory exceeds 2 MiB")
	}
	var i Inventory
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&i); err != nil {
		return Inventory{}, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return Inventory{}, errors.New("trailing signature inventory data")
	}
	if i.Format != "netcap-service-signature-inventory" || i.SchemaVersion != 1 || i.Scope != "capture" || i.CheckedAt.IsZero() {
		return Inventory{}, errors.New("invalid signature inventory")
	}
	if i.State == "loaded" {
		if i.Catalogue == nil || i.RuleCount != len(i.Catalogue.Rules) || (i.Source != "external" && i.Source != "builtin") || (i.Source == "builtin" && (!i.Degraded || i.Warning == "")) {
			return Inventory{}, errors.New("inconsistent loaded signature inventory")
		}
		digest, err := hex.DecodeString(i.SourceSHA256)
		if err != nil || len(digest) != 32 {
			return Inventory{}, errors.New("invalid signature source digest")
		}
		encoded, err := json.Marshal(i.Catalogue)
		if err != nil {
			return Inventory{}, err
		}
		if _, err = Parse(bytes.NewReader(encoded)); err != nil {
			return Inventory{}, err
		}
	} else if (i.State != "disabled" && i.State != "not-recorded" && i.State != "not-initialized") || i.Source != "none" || i.Catalogue != nil || i.RuleCount != 0 || i.SourceSHA256 != "" {
		return Inventory{}, errors.New("inconsistent unavailable signature inventory")
	}
	return i, nil
}
