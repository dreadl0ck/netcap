package firewallstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func ValidID(v string) bool  { return identifier.MatchString(v) }
func Digest(v string) string { d := sha256.Sum256([]byte(v)); return hex.EncodeToString(d[:]) }
func MatchToken(got, want string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return want != "" && subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

type Scope struct {
	Tenant string `json:"tenant"`
	App    string `json:"app"`
}

func (s Scope) Valid() bool { return ValidID(s.Tenant) && ValidID(s.App) }

type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string              { return e.Message }
func Fail(status int, message string) error { return &Error{status, message} }
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func WriteError(w http.ResponseWriter, err error) {
	status, message := 503, "operation unavailable"
	var e *Error
	if errors.As(err, &e) {
		status, message = e.Status, e.Message
	}
	WriteJSON(w, status, map[string]string{"error": message})
}

// Decode rejects duplicate keys as well as unknown fields and trailing input.
func Decode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON depth exceeded")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errors.New("duplicate JSON key")
					}
					seen[key] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("invalid JSON delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// Endpoint rejects credentials in URLs, redirects, and cleartext nonloopback
// peers. Loopback HTTP is only for local trusted deployments/tests.
func Endpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("base URL must contain scheme and host only")
	}
	ip := net.ParseIP(u.Hostname())
	loop := ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && loop) {
		return nil, errors.New("TLS required for nonloopback endpoint (use literal loopback IP for HTTP)")
	}
	return u, nil
}

// HTTPClient owns its timeout and redirect policy; transport customization may
// supply a trusted TLS root, but must not disable certificate verification.
func HTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxConnsPerHost = 16
		t.ResponseHeaderTimeout = timeout
		transport = t
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func RequestJSON(ctx context.Context, client *http.Client, method, endpoint, token string, input, output any, max int64) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	r, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > max {
		return errors.New("response exceeds limit")
	}
	if resp.StatusCode != 200 {
		return Fail(resp.StatusCode, "remote operation rejected")
	}
	return Decode(raw, output)
}

func Bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(v, "Bearer ")
}
