package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/dreadl0ck/netcap/internal/artifactio"
)

type hostIdentityReport struct {
	State  string         `json:"state"`
	Report map[string]any `json:"report,omitempty"`
}

// Keep scoped identities separate from the IP-only traffic aggregation.
func readHostIdentity(ctx context.Context, outDir string) (hostIdentityReport, error) {
	data, err := artifactio.Read(ctx, outDir, "Hosts.json", 32<<20)
	if errors.Is(err, os.ErrNotExist) {
		return hostIdentityReport{State: "unavailable"}, nil
	}
	if err != nil {
		return hostIdentityReport{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var report map[string]any
	if err := dec.Decode(&report); err != nil {
		return hostIdentityReport{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return hostIdentityReport{}, fmt.Errorf("trailing identity data")
	}
	if report == nil || report["schema"] != json.Number("1") {
		return hostIdentityReport{}, fmt.Errorf("unsupported identity schema")
	}
	if hosts, exists := report["hosts"]; !exists {
		return hostIdentityReport{}, fmt.Errorf("missing identity hosts")
	} else if hosts == nil {
		report["hosts"] = []any{}
	} else if _, ok := hosts.([]any); !ok {
		return hostIdentityReport{}, fmt.Errorf("invalid identity hosts")
	}
	for _, raw := range report["hosts"].([]any) {
		host, ok := raw.(map[string]any)
		if !ok {
			return hostIdentityReport{}, fmt.Errorf("invalid identity host")
		}
		for _, field := range []string{"ip", "scope", "hostnameState", "macState"} {
			if _, ok := host[field].(string); !ok {
				return hostIdentityReport{}, fmt.Errorf("invalid identity host %s", field)
			}
		}
	}
	quoteIdentityTimes(report)
	return hostIdentityReport{State: "available", Report: report}, nil
}

func quoteIdentityTimes(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if key == "at" {
				if n, ok := item.(json.Number); ok {
					v[key] = n.String()
				}
			} else {
				quoteIdentityTimes(item)
			}
		}
	case []any:
		for _, item := range v {
			quoteIdentityTimes(item)
		}
	}
}
