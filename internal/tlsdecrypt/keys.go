// Package tlsdecrypt authenticates passive TLS records using captured NSS key logs.
package tlsdecrypt

import (
	"encoding/hex"
	"strings"
	"sync"
)

type Secrets struct {
	mu        sync.RWMutex
	keys      map[string][]byte
	conflicts map[string]bool
}

func NewSecrets() *Secrets { return &Secrets{keys: map[string][]byte{}, conflicts: map[string]bool{}} }

// Add ignores malformed lines and permanently rejects conflicting secrets.
// Secret bytes are never returned in diagnostics or persisted outside the capture.
func (s *Secrets) Add(data []byte) {
	if len(data) > 4<<20 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || len(f[1]) != 64 || len(f[2]) > 128 {
			continue
		}
		switch f[0] {
		case "CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0":
		default:
			continue
		}
		random, err := hex.DecodeString(f[1])
		if err != nil {
			continue
		}
		secret, err := hex.DecodeString(f[2])
		if err != nil || len(secret) < 32 {
			continue
		}
		key := f[0] + ":" + hex.EncodeToString(random)
		if previous, ok := s.keys[key]; ok && string(previous) != string(secret) {
			delete(s.keys, key)
			s.conflicts[key] = true
		}
		if !s.conflicts[key] && len(s.keys)+len(s.conflicts) < 16384 {
			s.keys[key] = secret
		}
	}
}

func (s *Secrets) lookup(label string, random []byte) []byte {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[label+":"+hex.EncodeToString(random)]
}

func (s *Secrets) Empty() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys) == 0
}
