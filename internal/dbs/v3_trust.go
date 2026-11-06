package dbs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	ApprovalRegistryEnv    = "NC_DBS_APPROVALS"
	ApprovalRegistryPinEnv = "NC_DBS_APPROVALS_SHA256"
)

// A registry is operator configuration, not a member of a downloaded release.
// Its exact bytes must be pinned independently of server metadata/manifests.
type approvalTrust struct {
	SHA256  string
	Reviews []ReviewedSource
}

func configuredTrust(untrustedDirs ...string) (approvalTrust, error) {
	return loadApprovalTrust(os.Getenv(ApprovalRegistryEnv), os.Getenv(ApprovalRegistryPinEnv), untrustedDirs...)
}

// Community trust ships with the client, independently of downloaded manifests.
// Publishers still require an explicit operator registry.
func loadClientTrust(path, pin string, untrustedDirs ...string) (approvalTrust, error) {
	if path != "" || pin != "" {
		return loadApprovalTrust(path, pin, untrustedDirs...)
	}
	return parseApprovalTrust([]byte(communityRegistry), communityRegistrySHA256)
}

func loadApprovalTrust(path, pin string, untrustedDirs ...string) (approvalTrust, error) {
	if path == "" || !validDigest(pin) {
		return approvalTrust{}, fmt.Errorf("rights trust blocked: explicit reviewed records and independently pinned NC_DBS_APPROVALS_SHA256 are required")
	}
	registry, err := canonicalPath(path)
	if err != nil {
		return approvalTrust{}, err
	}
	for _, dir := range untrustedDirs {
		root, err := canonicalPath(dir)
		if err != nil {
			return approvalTrust{}, err
		}
		rel, err := filepath.Rel(root, registry)
		if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return approvalTrust{}, fmt.Errorf("operator approval registry must be outside candidate, release and cache directories")
		}
	}
	b, err := readRegularBytes(path, 16<<20)
	if err != nil {
		return approvalTrust{}, err
	}
	return parseApprovalTrust(b, pin)
}

func parseApprovalTrust(b []byte, pin string) (approvalTrust, error) {
	if !validDigest(pin) || digest(b) != pin {
		return approvalTrust{}, fmt.Errorf("operator approval registry digest mismatch")
	}
	var reviews []ReviewedSource
	if err := decodeJSON(b, &reviews); err != nil {
		return approvalTrust{}, fmt.Errorf("operator registry: %w", err)
	}
	if len(reviews) == 0 {
		return approvalTrust{}, fmt.Errorf("operator approval registry is empty")
	}
	seen := map[string]bool{}
	for _, r := range reviews {
		if err := validateReview(r); err != nil {
			return approvalTrust{}, err
		}
		key, _ := json.Marshal(r)
		if seen[string(key)] {
			return approvalTrust{}, fmt.Errorf("duplicate operator review")
		}
		seen[string(key)] = true
	}
	return approvalTrust{pin, reviews}, nil
}

func (trust approvalTrust) authorize(m ReleaseManifest) error {
	if !validDigest(trust.SHA256) || m.ApprovalRegistrySHA256 != trust.SHA256 {
		return fmt.Errorf("manifest is not bound to the configured operator approval registry")
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	for _, r := range m.Reviews {
		found := false
		for _, allowed := range trust.Reviews {
			if reflect.DeepEqual(allowed, r) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("manifest review %s is not present in the pinned operator registry", r.ReviewID)
		}
	}
	return nil
}

func openRegular(path string) (*os.File, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("non-regular evidence %s", path)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, fmt.Errorf("evidence changed while opening %s", path)
	}
	return f, nil
}

func readRegularBytes(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("oversized evidence %s", path)
	}
	return b, nil
}
