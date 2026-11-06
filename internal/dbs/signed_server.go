package dbs

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func currentSigned(dir string) (SignedRelease, ReleasePayload, error) {
	var envelope SignedRelease
	if dir == "" {
		return envelope, ReleasePayload{}, fmt.Errorf("signed channel not configured")
	}
	if err := readJSON(filepath.Join(dir, "signed-latest.json"), &envelope); err != nil {
		return envelope, ReleasePayload{}, err
	}
	p, _, _, err := verifyCommunityRelease(envelope, true)
	if err != nil {
		return envelope, p, err
	}
	f, err := openRegular(filepath.Join(dir, p.Metadata.Tarball))
	if err != nil {
		return envelope, p, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return envelope, p, err
	}
	if info.Size() != p.Metadata.Size {
		return envelope, p, fmt.Errorf("signed archive size mismatch")
	}
	sum, size, err := hashFile(filepath.Join(dir, p.Metadata.Tarball))
	if err != nil || size != p.Metadata.Size || sum != p.Metadata.SHA256 {
		return envelope, p, fmt.Errorf("signed archive hash mismatch")
	}
	return envelope, p, nil
}

func (s *DBServer) handleSigned(w http.ResponseWriter, r *http.Request) {
	dir := os.Getenv("NC_DBS_SIGNED_ROOT")
	envelope, p, err := currentSigned(dir)
	if err != nil {
		http.Error(w, "validated signed release unavailable", 503)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/dbs/signed/v1/")
	if name == "latest" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = jsonResponse(w, envelope)
		return
	}
	if name == p.Metadata.Tarball {
		serveVerifiedObject(w, r, filepath.Join(dir, name), p.Metadata)
		return
	}
	// In-flight updates keep digest downloads available after latest advances.
	id := strings.TrimSuffix(name, ".tar.gz")
	if id != name && validDigest(id) {
		var meta DBMetadata
		if readJSON(filepath.Join(dir, id+".json"), &meta) == nil && meta.Tarball == name && validateV3Metadata(&meta) == nil {
			serveVerifiedObject(w, r, filepath.Join(dir, name), meta)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *DBServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "compatibility release unavailable", 503)
		return
	}
	_, p, err := currentSigned(os.Getenv("NC_DBS_SIGNED_ROOT"))
	if err != nil {
		http.Error(w, "signed release unavailable or expired", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = jsonResponse(w, map[string]any{"status": "ready", "sequence": p.Sequence, "expires_at": p.ExpiresAt, "version": p.Metadata.Version, "policy_sha256": p.PolicySHA256})
}

func (s *DBServer) handleFreshness(w http.ResponseWriter, r *http.Request) {
	e, p, err := currentSigned(os.Getenv("NC_DBS_SIGNED_ROOT"))
	if err != nil {
		http.Error(w, "signed release unavailable or expired", 503)
		return
	}
	_, _, key, err := verifyCommunityRelease(e, true)
	if err != nil {
		http.Error(w, "signing key unavailable", 503)
		return
	}
	if time.Until(time.Unix(p.ExpiresAt, 0)) < 24*time.Hour {
		http.Error(w, "database refresh overdue", 503)
		return
	}
	if time.Until(time.Unix(key.NotAfter, 0)) < 14*24*time.Hour {
		http.Error(w, "publisher key rotation due within 14 days", 503)
		return
	}
	if time.Until(time.Unix(p.PolicyExpiresAt, 0)) < 14*24*time.Hour {
		http.Error(w, "source policy renewal due within 14 days", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = jsonResponse(w, map[string]any{"status": "fresh", "expires_at": p.ExpiresAt, "key_expires_at": key.NotAfter})
}
