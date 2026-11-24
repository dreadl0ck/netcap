package webui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

const visitorCookie = "netcap_visitor"

func visitorDigest(r *http.Request) string {
	cookie, err := r.Cookie(visitorCookie)
	if err != nil || len(cookie.Value) != 64 {
		return ""
	}
	value, err := hex.DecodeString(cookie.Value)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func ensureVisitor(w http.ResponseWriter, r *http.Request) string {
	if digest := visitorDigest(r); digest != "" {
		return digest
	}
	var key [32]byte
	rand.Read(key[:])
	http.SetCookie(w, serviceCookie(r, visitorCookie, hex.EncodeToString(key[:])))
	hash := sha256.Sum256(key[:])
	return hex.EncodeToString(hash[:])
}

func serviceCookie(r *http.Request, name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteLaxMode}
}

func sessionVisible(r *http.Request, session *SessionInfo) bool {
	if session.IsPreloaded || captureAdminAuthorized(r) {
		return true
	}
	digest := visitorDigest(r)
	return digest != "" && subtle.ConstantTimeCompare([]byte(digest), []byte(session.visitorHash)) == 1
}

func (s *Server) visibleSession(r *http.Request, id string) (*SessionInfo, bool) {
	if s.sessionManager == nil {
		return nil, false
	}
	session, ok := s.sessionManager.GetSession(id)
	if !ok || !sessionVisible(r, session) {
		return nil, false
	}
	return session, true
}

func (s *Server) visibleSessions(r *http.Request) []*SessionInfo {
	var sessions []*SessionInfo
	for _, session := range s.sessionManager.GetAllSessions() {
		if sessionVisible(r, session) {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

func (s *Server) preloadedSelection(r *http.Request) bool {
	if !s.isServiceMode {
		return false
	}
	selection, err := s.resolveCaptureSelection(r)
	if err != nil {
		return false
	}
	session, ok := s.visibleSession(r, selection.SessionID)
	return ok && session.IsPreloaded && session.Status == StatusCompleted
}
