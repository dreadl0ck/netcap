// Package firewalltransport gates complete messages before releasing their wire headers.
package firewalltransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxMessageBytes = 1 << 20

type Capabilities struct {
	WebSocket            bool
	GRPC                 bool
	HTTP3                bool
	MaxMessageBytes      int
	WebSocketCompression bool
	GRPCEncodings        []string
	GRPCHTTPVersions     []int
}

func Supported() Capabilities {
	return Capabilities{WebSocket: true, GRPC: true, HTTP3: HTTP3Available, MaxMessageBytes: MaxMessageBytes, GRPCEncodings: []string{"identity", "gzip"}, GRPCHTTPVersions: []int{2}}
}

// Event carries one message, never the accumulated connection or RPC stream.
// Attributes are separate so callers can bridge to their policy model explicitly.
type Event struct {
	// Payload is borrowed for the callback duration when Config.ByteEvents is true.
	Payload                                             []byte
	Protocol, Phase, Method, Host, Path, RawQuery, Body string
	Status                                              int
	Headers                                             http.Header
	Attributes                                          map[string]string
}

type InspectFunc func(context.Context, Event) error

// Rejection preserves an HTTP decision until a streaming response is committed.
type Rejection struct{ Status int }

func (r Rejection) Error() string { return http.StatusText(r.Status) }
func (r Rejection) Unwrap() error { return ErrDenied }
func inspectionStatus(err error) int {
	if errors.Is(err, ErrBufferCapacity) {
		return 503
	}
	var reject Rejection
	if errors.As(err, &reject) && reject.Status >= 400 && reject.Status <= 599 {
		return reject.Status
	}
	return 403
}

// Config is opt-in. Next handles all traffic outside the explicitly enabled modes.
// Transport must support HTTP/2 for streaming gRPC (including TLS ALPN).
type Config struct {
	ByteEvents         bool
	Budget             *BufferBudget
	MaxBufferedBytes   int64
	Context            context.Context
	Begin              func(*http.Request) InspectFunc
	End                func(*http.Request)
	WebSocket          bool
	GRPC               bool
	Upstream           *url.URL
	Transport          http.RoundTripper
	WebSocketTransport http.RoundTripper
	MessageTimeout     time.Duration
	MaxConcurrent      int
}

type Handler struct {
	cfg                    Config
	next                   http.Handler
	inspect                InspectFunc
	slots                  chan struct{}
	ownsWebSocketTransport bool
}

func New(c Config, next http.Handler, inspect InspectFunc) (*Handler, error) {
	if c.MaxBufferedBytes == 0 {
		c.MaxBufferedBytes = DefaultMaxBufferedBytes
	}
	if c.MaxBufferedBytes < 1 || c.MaxBufferedBytes > MaxBufferBudgetBytes {
		return nil, errors.New("max buffered bytes must be 1..1073741824")
	}
	if c.Budget == nil {
		c.Budget, _ = NewBufferBudget(c.MaxBufferedBytes)
	} else {
		c.MaxBufferedBytes = c.Budget.Limit()
	}
	if next == nil {
		return nil, errors.New("fallback handler required")
	}
	if c.MaxConcurrent < 0 || c.MaxConcurrent > 4096 {
		return nil, errors.New("concurrency must be 0..4096")
	}
	if c.WebSocket || c.GRPC {
		if (inspect == nil && c.Begin == nil) || c.Upstream == nil || c.Upstream.Host == "" || (c.Upstream.Scheme != "http" && c.Upstream.Scheme != "https") || c.Upstream.User != nil || c.Upstream.RawQuery != "" || c.Upstream.Fragment != "" || (c.Upstream.Path != "" && c.Upstream.Path != "/") {
			return nil, errors.New("message inspection requires inspector and HTTP(S) upstream origin")
		}
		if c.MessageTimeout <= 0 || c.MessageTimeout > 5*time.Minute || c.MaxConcurrent < 1 || c.MaxConcurrent > 4096 {
			return nil, errors.New("explicit message timeout (<=5m) and concurrency (1..4096) required")
		}
	}
	if c.Transport == nil {
		c.Transport = http.DefaultTransport
	}
	ownsWS := false
	if c.WebSocket && c.WebSocketTransport == nil {
		if base, ok := c.Transport.(*http.Transport); ok {
			ws := base.Clone()
			ws.ForceAttemptHTTP2 = false
			ws.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			ws.TLSClientConfig = ws.TLSClientConfig.Clone()
			if ws.TLSClientConfig == nil {
				ws.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			ws.TLSClientConfig.NextProtos = []string{"http/1.1"}
			c.WebSocketTransport = ws
			ownsWS = true
		} else {
			c.WebSocketTransport = c.Transport
		}
	}
	if c.Upstream != nil {
		u := *c.Upstream
		c.Upstream = &u
	}
	return &Handler{cfg: c, next: next, inspect: inspect, slots: make(chan struct{}, c.MaxConcurrent), ownsWebSocketTransport: ownsWS}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	grpc := grpcMediaType(r.Header.Get("Content-Type"))
	if !(ws && h.cfg.WebSocket || grpc && h.cfg.GRPC) {
		h.next.ServeHTTP(w, r)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "message capacity exhausted", 503)
		return
	}
	if r.Method == "" || len(r.Method)+len(r.Host)+len(r.URL.RequestURI()) > 64<<10 || !validHeaders(r.Header) {
		http.Error(w, "oversized metadata", 431)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if h.cfg.Context != nil {
		if h.cfg.Context.Err() != nil {
			http.Error(w, "transport closed", 503)
			return
		}
		stop := context.AfterFunc(h.cfg.Context, cancel)
		defer stop()
	}
	r = r.WithContext(ctx)
	if h.cfg.Begin != nil {
		local := *h
		local.inspect = h.cfg.Begin(r)
		if local.inspect == nil {
			http.Error(w, "inspector unavailable", 503)
			return
		}
		if h.cfg.End != nil {
			defer h.cfg.End(r)
		}
		h = &local
	}
	protocol := "grpc"
	if ws {
		protocol = "websocket"
	}
	if err := h.inspect(r.Context(), event(r, protocol, "request", nil, 0)); err != nil {
		http.Error(w, "request denied", inspectionStatus(err))
		return
	}
	if ws {
		h.webSocket(w, r)
	} else {
		h.grpc(w, r)
	}
}

func grpcMediaType(value string) bool {
	media := strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	return media == "application/grpc" || strings.HasPrefix(media, "application/grpc+") && len(media) > len("application/grpc+")
}

func validHeaders(h http.Header) bool {
	n, values := 0, 0
	if len(h) > 128 {
		return false
	}
	for k, vs := range h {
		if len(k) > 1024 {
			return false
		}
		n += len(k)
		values += len(vs)
		for _, v := range vs {
			n += len(v)
		}
		if n > 32<<10 || values > 1024 {
			return false
		}
	}
	return true
}

func event(r *http.Request, protocol, phase string, body []byte, status int) Event {
	return Event{Protocol: protocol, Phase: phase, Method: r.Method, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Body: string(body), Status: status, Headers: r.Header.Clone(), Attributes: map[string]string{"http.url": r.URL.RequestURI(), "inspection.kind": "headers"}}
}

func (h *Handler) messageEvent(r *http.Request, protocol, phase string, body []byte, status int) Event {
	e := event(r, protocol, phase, nil, status)
	if h.cfg.ByteEvents {
		e.Payload = body
	} else {
		e.Body = string(body)
	}
	return e
}

func (h *Handler) outbound(r *http.Request, ctx context.Context) *http.Request {
	out := r.Clone(ctx)
	out.URL.Scheme, out.URL.Host = h.cfg.Upstream.Scheme, h.cfg.Upstream.Host
	out.RequestURI = ""
	// Client-supplied forwarding identities must never become trusted upstream.
	for k := range out.Header {
		l := strings.ToLower(k)
		if l == "forwarded" || l == "x-real-ip" || strings.HasPrefix(l, "x-forwarded-") || l == "proxy-authorization" || l == "proxy-connection" {
			out.Header.Del(k)
		}
	}
	return out
}

func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			continue
		}
		dst[k] = append([]string(nil), v...)
	}
}
