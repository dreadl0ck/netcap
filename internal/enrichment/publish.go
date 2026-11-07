package enrichment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SignPublication consumes an existing separately delegated signer; it never creates or changes keys.
func SignPublication(dir, keyPath, certPath string, sequence uint64, trust ed25519.PublicKey, now time.Time) error {
	raw, e := regular(filepath.Join(dir, "unsigned-payload.json"), 1<<20)
	if e != nil {
		return e
	}
	var p Payload
	if e = decode(raw, &p); e != nil {
		return e
	}
	kb, e := regular(keyPath, 1024)
	if e != nil {
		return e
	}
	key, e := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(kb)))
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid existing enrichment signer")
	}
	cb, e := regular(certPath, 8192)
	if e != nil {
		return e
	}
	var cert SignedBytes
	if e = decode(cb, &cert); e != nil {
		return e
	}
	p.Sequence = sequence
	p.IssuedAt = now.Unix()
	p.ExpiresAt = now.Add(72 * time.Hour).Unix()
	payload, e := json.Marshal(p)
	if e != nil {
		return e
	}
	env := Envelope{cert, SignedBytes{payload, ed25519.Sign(key, payload)}}
	if _, _, e = Verify(env, trust, now, true); e != nil {
		return e
	}
	archive, e := regular(filepath.Join(dir, p.ArchiveSHA256+".tar.gz"), MaxArchive)
	if e != nil {
		return e
	}
	if _, e = unpack(archive, p); e != nil {
		return e
	}
	lockPath := filepath.Join(dir, ".publish.lock")
	lock, e := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer func() { lock.Close(); os.Remove(lockPath) }()
	if previous, e := readEnvelope(filepath.Join(dir, "signed-latest.json")); e == nil {
		if e = CheckOrder(env, previous, trust, now); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	b, e := json.Marshal(env)
	if e != nil {
		return e
	}
	immutable := filepath.Join(dir, fmt.Sprintf("signed-%d.json", sequence))
	if existing, e := regular(immutable, 2<<20); e == nil {
		if !bytes.Equal(existing, b) {
			return fmt.Errorf("immutable enrichment sequence conflict")
		}
	} else if os.IsNotExist(e) {
		if e = write(immutable, b); e != nil {
			return e
		}
	} else {
		return e
	}
	f, e := os.CreateTemp(dir, ".latest-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, filepath.Join(dir, "signed-latest.json"))
}

// Handler serves only a completely verified optional publication. Mount separately from /dbs/.
func Handler(dir string, trust ed25519.PublicKey) (http.Handler, error) {
	env, e := readEnvelope(filepath.Join(dir, "signed-latest.json"))
	if e != nil {
		return nil, e
	}
	p, _, e := Verify(env, trust, time.Now(), true)
	if e != nil {
		return nil, e
	}
	archive, e := regular(filepath.Join(dir, p.ArchiveSHA256+".tar.gz"), MaxArchive)
	if e != nil {
		return nil, e
	}
	members, e := unpack(archive, p)
	if e != nil {
		return nil, e
	}
	metadata, e := json.Marshal(env)
	if e != nil {
		return nil, e
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if _, _, e := Verify(env, trust, time.Now(), true); e != nil {
			http.Error(w, "optional enrichment publication expired", http.StatusServiceUnavailable)
			return
		}
		var b []byte
		switch r.URL.Path {
		case "/enrichment/ready":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ready", "channel": Channel, "minimum_format": 1, "capabilities": []string{Capability}, "sequence": p.Sequence, "expires_at": p.ExpiresAt, "archive_sha256": p.ArchiveSHA256, "archive_size": p.ArchiveSize})
			return
		case "/enrichment/signed/v1/latest":
			b = metadata
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
		case "/enrichment/signed/v1/" + p.ArchiveSHA256 + ".tar.gz":
			b = archive
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			prefix := "/enrichment/signed/v1/" + p.ArchiveSHA256 + "/"
			name := strings.TrimPrefix(r.URL.Path, prefix)
			var ok bool
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			b, ok = members[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeContent(w, r, strings.TrimPrefix(r.URL.Path, "/"), time.Time{}, bytes.NewReader(b))
	}), nil
}

func VerifyPublication(dir string, trust ed25519.PublicKey, now time.Time) error {
	return verifyPublication(dir, trust, now, true)
}

func verifyPublication(dir string, trust ed25519.PublicKey, now time.Time, fresh bool) error {
	env, e := readEnvelope(filepath.Join(dir, "signed-latest.json"))
	if e != nil {
		return e
	}
	p, _, e := Verify(env, trust, now, fresh)
	if e != nil {
		return e
	}
	archive, e := regular(filepath.Join(dir, p.ArchiveSHA256+".tar.gz"), MaxArchive)
	if e != nil {
		return e
	}
	members, e := unpack(archive, p)
	if e != nil {
		return e
	}
	var sources []Source
	if e = decode(members[SourcesName], &sources); e != nil {
		return e
	}
	if len(sources) != 5 {
		return fmt.Errorf("production optional publication requires all five reviewed sources")
	}
	for _, s := range sources {
		if s.Review == nil {
			return fmt.Errorf("missing automated publication review: %s", s.ID)
		}
	}
	return nil
}

func PreviousKEVCount(dir string, trust ed25519.PublicKey, now time.Time) (int, error) {
	env, e := readEnvelope(filepath.Join(dir, "signed-latest.json"))
	if e != nil {
		return 0, e
	}
	p, _, e := Verify(env, trust, now, false)
	if e != nil {
		return 0, e
	}
	b, e := regular(filepath.Join(dir, p.ArchiveSHA256+".tar.gz"), MaxArchive)
	if e != nil {
		return 0, e
	}
	members, e := unpack(b, p)
	if e != nil {
		return 0, e
	}
	catalog, e := ParseKEV(members["kev.json"])
	if e != nil {
		return 0, e
	}
	return catalog.Count, nil
}

// LiveHandler follows the atomically published pointer without a container restart.
func LiveHandler(dir string, trust ed25519.PublicKey) (http.Handler, error) {
	if e := verifyPublication(dir, trust, time.Now(), false); e != nil {
		return nil, e
	}
	var mu sync.Mutex
	var cached http.Handler
	var identity string
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enrichment/live" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "serving", "channel": Channel})
			return
		}
		if serveHistorical(dir, trust, w, r) {
			return
		}
		if r.URL.Path == "/enrichment/freshness" {
			b, e := regular(filepath.Join(dir, "refresh-status.json"), 4096)
			if e == nil {
				var status struct {
					Format     string `json:"format"`
					State      string `json:"state"`
					Stage      string `json:"stage"`
					ObservedAt string `json:"observed_at"`
				}
				if decode(b, &status) != nil || status.State == "failed" {
					http.Error(w, "optional enrichment refresh failed", http.StatusServiceUnavailable)
					return
				}
			}
		}
		mu.Lock()
		b, e := regular(filepath.Join(dir, "signed-latest.json"), 2<<20)
		if e == nil && Digest(b) != identity {
			e = VerifyPublication(dir, trust, time.Now())
			if e == nil {
				cached, e = Handler(dir, trust)
				if e == nil {
					identity = Digest(b)
				}
			}
		}
		handler := cached
		mu.Unlock()
		if e != nil || handler == nil {
			http.Error(w, "optional enrichment publication unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/enrichment/freshness" {
			copy := r.Clone(r.Context())
			url := *r.URL
			url.Path = "/enrichment/ready"
			copy.URL = &url
			handler.ServeHTTP(w, copy)
			return
		}
		handler.ServeHTTP(w, r)
	}), nil
}

// Immutable source offerings remain available after the current pointer advances or its lease expires.
func serveHistorical(dir string, trust ed25519.PublicKey, w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/enrichment/signed/v1/")
	if path == r.URL.Path || path == "latest" {
		return false
	}
	hash, member, hasMember := strings.Cut(path, "/")
	if !hasMember {
		hash = strings.TrimSuffix(hash, ".tar.gz")
		if hash+".tar.gz" != path {
			return false
		}
	}
	if !validDigest(hash) || (hasMember && SourceFor(member) == "" && member != ManifestName && member != SourcesName && member != NoticesName) {
		http.NotFound(w, r)
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		http.NotFound(w, r)
		return true
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "signed-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		env, e := readEnvelope(filepath.Join(dir, entry.Name()))
		if e != nil {
			continue
		}
		p, _, e := Verify(env, trust, time.Now(), false)
		if e != nil || p.ArchiveSHA256 != hash {
			continue
		}
		archive, e := regular(filepath.Join(dir, hash+".tar.gz"), MaxArchive)
		if e != nil {
			continue
		}
		members, e := unpack(archive, p)
		if e != nil {
			continue
		}
		data := archive
		mime := "application/gzip"
		if hasMember {
			var ok bool
			data, ok = members[member]
			if !ok {
				http.NotFound(w, r)
				return true
			}
			mime = "application/octet-stream"
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, path, time.Time{}, bytes.NewReader(data))
		return true
	}
	http.NotFound(w, r)
	return true
}

// Resolve returns the verified active immutable directory for domain-specific readers.
func Resolve(root string, trust ed25519.PublicKey, now time.Time) (string, error) {
	dir, e := activeDir(root)
	if e != nil {
		return "", e
	}
	if _, e = OpenVersion(dir, trust, now, true); e != nil {
		return "", e
	}
	return dir, nil
}
