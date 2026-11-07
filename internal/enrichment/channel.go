// Package enrichment implements an optional, offline-readable channel independent of netcap.sqlite.
package enrichment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

const Channel = "community-enrichment"
const Capability = "netcap-enrichment/v1"
const ManifestName = "ENRICHMENT_MANIFEST.json"
const NoticesName = "ENRICHMENT_NOTICES.txt"
const SourcesName = "source-evidence.json"
const MaxMember = 64 << 20
const MaxArchive = 256 << 20

// Signatures cover original bytes, using the existing community root and delegated-key envelope.
type SignedBytes struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Envelope struct {
	Certificate SignedBytes `json:"certificate"`
	SignedBytes
}

// A core signing certificate cannot authorize this channel. The offline root must grant this exact scope.
type Key struct {
	Format        string   `json:"format"`
	PublicKey     []byte   `json:"public_key"`
	Epoch         uint64   `json:"epoch"`
	NotBefore     int64    `json:"not_before"`
	NotAfter      int64    `json:"not_after"`
	Channel       string   `json:"channel"`
	Capabilities  []string `json:"capabilities"`
	MinimumFormat uint64   `json:"minimum_format"`
}
type Payload struct {
	Format         string   `json:"format"`
	Channel        string   `json:"channel"`
	Sequence       uint64   `json:"sequence"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	MinimumFormat  uint64   `json:"minimum_format"`
	Capabilities   []string `json:"capabilities"`
	ArchiveSHA256  string   `json:"archive_sha256"`
	ArchiveSize    int64    `json:"archive_size"`
	ManifestSHA256 string   `json:"manifest_sha256"`
}
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Manifest struct {
	Format string `json:"format"`
	Files  []File `json:"files"`
}

// Source binds the full acquired grant and transformation to exact output bytes. It is evidence, not a fabricated approval.
type Source struct {
	ID             string  `json:"id"`
	Origin         string  `json:"origin"`
	Revision       string  `json:"revision"`
	InputSHA256    string  `json:"input_sha256"`
	GrantOrigin    string  `json:"grant_origin"`
	GrantRevision  string  `json:"grant_revision"`
	GrantText      string  `json:"grant_text"`
	GrantSHA256    string  `json:"grant_sha256"`
	Transformation string  `json:"transformation"`
	Outputs        []File  `json:"outputs"`
	Evidence       string  `json:"evidence,omitempty"`
	Review         *Review `json:"review,omitempty"`
}

type Review struct {
	Decision       string `json:"decision"`
	Reviewer       string `json:"reviewer"`
	ReviewID       string `json:"review_id"`
	ReviewedAt     string `json:"reviewed_at"`
	Authorization  string `json:"authorization"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func decode(b []byte, v any) error {
	if !utf8.Valid(b) {
		return fmt.Errorf("invalid UTF-8 enrichment JSON")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(b)), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("enrichment JSON nesting limit")
	}
	token, e := d.Token()
	if e != nil {
		return e
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return fmt.Errorf("duplicate enrichment JSON key")
			}
			seen[s] = true
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	case json.Delim('['):
		for d.More() {
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	}
	return nil
}
func exactCapabilities(c []string) bool { return len(c) == 1 && c[0] == Capability }
func Verify(e Envelope, root ed25519.PublicKey, now time.Time, fresh bool) (Payload, Key, error) {
	var p Payload
	var k Key
	fail := func() (Payload, Key, error) {
		return p, k, fmt.Errorf("invalid enrichment signature, scope or validity")
	}
	if len(root) != 32 || len(e.Certificate.Payload) > 4096 || !ed25519.Verify(root, e.Certificate.Payload, e.Certificate.Signature) {
		return fail()
	}
	if decode(e.Certificate.Payload, &k) != nil || k.Format != "netcap-enrichment-signing-key/v1" || len(k.PublicKey) != 32 || k.Epoch == 0 || k.Channel != Channel || k.MinimumFormat != 1 || !exactCapabilities(k.Capabilities) || k.NotAfter <= k.NotBefore || uint64(k.NotAfter)-uint64(k.NotBefore) > 90*86400 {
		return fail()
	}
	if len(e.Payload) > 1<<20 || !ed25519.Verify(k.PublicKey, e.Payload, e.Signature) {
		return fail()
	}
	if decode(e.Payload, &p) != nil || p.Format != "netcap-enrichment-release/v1" || p.Channel != Channel || p.MinimumFormat != 1 || !exactCapabilities(p.Capabilities) || p.Sequence == 0 || p.IssuedAt < k.NotBefore || p.IssuedAt > now.Unix()+300 || p.ExpiresAt > k.NotAfter || p.ExpiresAt <= p.IssuedAt || uint64(p.ExpiresAt)-uint64(p.IssuedAt) > 7*86400 || !validDigest(p.ArchiveSHA256) || !validDigest(p.ManifestSHA256) || p.ArchiveSize <= 0 || p.ArchiveSize > MaxArchive {
		return fail()
	}
	if fresh && (now.Unix() >= p.ExpiresAt || now.Unix() < k.NotBefore) {
		return fail()
	}
	return p, k, nil
}
func CheckOrder(next Envelope, previous Envelope, root ed25519.PublicKey, now time.Time) error {
	n, nk, e := Verify(next, root, now, true)
	if e != nil {
		return e
	}
	p, pk, e := Verify(previous, root, now, false)
	if e != nil {
		return e
	}
	if nk.Epoch < pk.Epoch || n.Sequence < p.Sequence || (n.Sequence == p.Sequence && (!bytes.Equal(next.Payload, previous.Payload) || !bytes.Equal(next.Certificate.Payload, previous.Certificate.Payload))) {
		return fmt.Errorf("enrichment rollback or equal-sequence equivocation")
	}
	return nil
}
func SourceFor(name string) string {
	switch name {
	case "kev.json":
		return "cisa-kev"
	case "dhcp-fingerprints-odbl.json":
		return "fingerbank-odbl"
	case "mac-organizations.json":
		return "mac-organizations"
	case "webtech-descriptors.json":
		return "webtech-descriptors"
	case "service-signatures.json":
		return "netcap-service-signatures"
	}
	return ""
}
