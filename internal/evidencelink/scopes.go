package evidencelink

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

func (idx *Index) loadScopes(dir string) error {
	idx.scopeStatus = "legacy"
	file, err := os.Open(filepath.Join(dir, "scope-manifest.json"))
	if os.IsNotExist(err) {
		file, err = os.Open(filepath.Join(dir, "capture-manifest.json"))
	}
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 16<<20 {
		return errors.New("capture manifest exceeds 16 MiB")
	}
	var manifest struct {
		RunID  string                `json:"runId"`
		Scopes *evidence.ScopeLedger `json:"communityScopes"`
	}
	hash := sha256.Sum256(data)
	idx.manifestSHA = hex.EncodeToString(hash[:])
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	idx.captureID = manifest.RunID
	if manifest.Scopes == nil {
		return nil
	}
	l := manifest.Scopes
	if l.Schema != 1 || len(l.Entries) > evidence.MaxCommunityScopes || manifest.RunID == "" {
		return errors.New("invalid capture scope ledger")
	}
	idx.scopes = make(map[string]evidence.CommunityScope)
	for _, entry := range l.Entries {
		if !strings.HasPrefix(entry.CommunityID, "1:") || len(entry.CommunityID) > 128 || len(entry.Scope.Sensor) > 64 || entry.Scope.Sensor == "" || entry.Scope.InterfaceIndex < 0 || len(entry.Scope.VLANs) > 4 {
			return errors.New("invalid capture scope entry")
		}
		for _, vlan := range entry.Scope.VLANs {
			if vlan > 4095 {
				return errors.New("invalid capture VLAN")
			}
		}
		if _, exists := idx.scopes[entry.CommunityID]; exists {
			return errors.New("duplicate capture scope entry")
		}
		idx.scopes[entry.CommunityID] = entry
	}
	idx.scopeStatus = "ready"
	if !l.Complete {
		idx.scopeStatus = "pending"
	}
	if l.Overflow != 0 {
		idx.scopeStatus = "overflow"
	}
	return nil
}

func (idx *Index) scopeFor(cid string) *evidence.FlowScope {
	if idx.scopeStatus != "ready" {
		return nil
	}
	entry, ok := idx.scopes[cid]
	if !ok || entry.Ambiguous {
		return nil
	}
	scope := entry.Scope
	return &scope
}

func sameRecordScope(a, b *evidence.FlowScope) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Sensor != b.Sensor || a.InterfaceIndex != b.InterfaceIndex || len(a.VLANs) != len(b.VLANs) {
		return false
	}
	for i := range a.VLANs {
		if a.VLANs[i] != b.VLANs[i] {
			return false
		}
	}
	return true
}
