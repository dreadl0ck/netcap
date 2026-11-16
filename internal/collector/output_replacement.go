package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
)

type outputReplacement struct {
	out, backup    string
	names          []string
	prepared       bool
	preserveAlerts bool
}

func (tx *outputReplacement) owns(name string) bool {
	return managedCaptureOutput(name) && !(tx.preserveAlerts && strings.HasPrefix(name, "Alert."))
}

func managedCaptureOutput(name string) bool {
	for _, suffix := range []string{".ncap", ".ncap.gz", ".csv", ".csv.gz", ".json.gz"} {
		if strings.HasSuffix(name, suffix) {
			_, known := types.Type_value["NC_"+strings.TrimSuffix(name, suffix)]
			return known
		}
	}
	switch name {
	case "AggregateStateHealth.json", "FlowExportsHealth.json", "FlowExports.jsonl", "capture-manifest.json", "capture-input.json", "audit-output-ready.json", "artifact-analysis.json", "packet-normalization.json", "enrichment-status.json",
		"tcp", "udp", "network", "stream-evidence", "packet-evidence", defaults.FileStorage:
		return true
	}
	return false
}

func (c *Collector) prepareOutputReplacement() (*outputReplacement, error) {
	out := c.config.DecoderConfig.Out
	if out == "" {
		out = "."
	}
	if err := os.MkdirAll(out, c.config.OutDirPermission); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		return nil, err
	}
	var names []string
	preserveAlerts := c.behaviorEngine != nil
	hasRun := false
	for _, entry := range entries {
		if managedCaptureOutput(entry.Name()) && !(preserveAlerts && strings.HasPrefix(entry.Name(), "Alert.")) {
			names = append(names, entry.Name())
			if entry.Name() != defaults.FileStorage {
				hasRun = true
			}
		}
	}
	if !hasRun {
		return nil, nil
	}
	if !c.config.NoPrompt {
		if !utils.StdinIsTerminal() {
			return nil, fmt.Errorf("%w: output path %q is not empty and stdin is not a terminal; pass -y to overwrite", errNotInteractive, out)
		}
		ok, err := utils.Confirm("Data from previous runs found in output path! Overwrite?")
		if err != nil {
			return nil, fmt.Errorf("%w: reading confirmation: %v", errNotInteractive, err)
		}
		if !ok {
			return nil, errAborted
		}
	}
	backup, err := os.MkdirTemp(out, ".netcap-overwrite-")
	if err != nil {
		return nil, err
	}
	tx := &outputReplacement{out: out, backup: backup, preserveAlerts: preserveAlerts}
	for _, name := range names {
		if err := os.Rename(filepath.Join(out, name), filepath.Join(backup, name)); err != nil {
			return nil, errors.Join(err, tx.rollback())
		}
		tx.names = append(tx.names, name)
	}
	tx.prepared = true
	return tx, nil
}

func (tx *outputReplacement) rollback() error {
	var result error
	if tx.prepared {
		entries, err := os.ReadDir(tx.out)
		result = errors.Join(result, err)
		for _, entry := range entries {
			if tx.owns(entry.Name()) {
				result = errors.Join(result, os.RemoveAll(filepath.Join(tx.out, entry.Name())))
			}
		}
	}
	for _, name := range tx.names {
		if err := os.RemoveAll(filepath.Join(tx.out, name)); err != nil {
			result = errors.Join(result, err)
			continue
		}
		result = errors.Join(result, os.Rename(filepath.Join(tx.backup, name), filepath.Join(tx.out, name)))
	}
	if result == nil {
		result = os.RemoveAll(tx.backup)
	}
	return result
}

func (tx *outputReplacement) commit() error { return os.RemoveAll(tx.backup) }
