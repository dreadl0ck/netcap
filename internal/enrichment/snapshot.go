package enrichment

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"time"
)

type Snapshot struct {
	State          string `json:"state"`
	ReleaseSHA256  string `json:"releaseSHA256,omitempty"`
	ArchiveSHA256  string `json:"archiveSHA256,omitempty"`
	ManifestSHA256 string `json:"manifestSHA256,omitempty"`
	Sequence       uint64 `json:"sequence,omitempty"`
	IssuedAt       int64  `json:"issuedAt,omitempty"`
	ExpiresAt      int64  `json:"expiresAt,omitempty"`
	Error          string `json:"error,omitempty"`
}

func runtimeDir(root string) (string, error) {
	if id := os.Getenv("NC_ENRICHMENT_VERSION"); id != "" {
		if !validDigest(id) {
			return "", os.ErrInvalid
		}
		return filepath.Join(root, "versions", id), nil
	}
	return activeDir(root)
}

// Inspect rechecks authenticity and content; an expired freshness lease does not alter offline data.
func Inspect(root string, trust ed25519.PublicKey, now time.Time) Snapshot {
	s := Snapshot{State: "invalid"}
	dir, err := runtimeDir(root)
	if err == nil {
		_, err = OpenVersion(dir, trust, now, false)
	}
	if err != nil {
		if os.IsNotExist(err) {
			s.State = "missing"
		}
		s.Error = err.Error()
		return s
	}
	envelope, err := readEnvelope(filepath.Join(dir, "signed-release.json"))
	if err != nil {
		s.Error = err.Error()
		return s
	}
	p, _, err := Verify(envelope, trust, now, false)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	s.State = "verified"
	if now.Unix() >= p.ExpiresAt {
		s.State = "stale"
	}
	s.ReleaseSHA256, s.ArchiveSHA256, s.ManifestSHA256 = Digest(envelope.Payload), p.ArchiveSHA256, p.ManifestSHA256
	s.Sequence, s.IssuedAt, s.ExpiresAt = p.Sequence, p.IssuedAt, p.ExpiresAt
	return s
}
