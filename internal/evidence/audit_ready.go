package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const AuditReadyFile = "audit-output-ready.json"

// MarkAuditOutputReady is called only after stream finalization and writer teardown.
func (c *Capture) MarkAuditOutputReady() (resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed || c.manifest.Status == "running" || c.manifest.Status == "error" || c.manifest.Error != "" || c.storageError != nil {
		return fmt.Errorf("cannot mark unfinished or failed audit output ready")
	}
	root, err := os.OpenRoot(c.directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	file, err := root.OpenFile(".audit-output-ready.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(".audit-output-ready.tmp")
	data := struct {
		Version int    `json:"version"`
		RunID   string `json:"runId"`
	}{Version: 1, RunID: c.manifest.RunID}
	writeErr := json.NewEncoder(file).Encode(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if _, err := root.Lstat(AuditReadyFile); !os.IsNotExist(err) {
		return fmt.Errorf("audit-ready output already exists or is inaccessible")
	}
	return root.Rename(".audit-output-ready.tmp", AuditReadyFile)
}
