package waf

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type Firewall struct {
	bootstrap sync.Mutex
	started   bool
	evaluator atomic.Pointer[evaluatorHook]
	readiness atomic.Pointer[readinessHook]
	buffers   *firewalltransport.BufferBudget
	cfg       Config
	current   atomic.Pointer[policy.Compiled]
	draining  atomic.Bool
	slots     chan struct{}
	proxy     *httputil.ReverseProxy
	transport *http.Transport
	trusted   []netip.Prefix
	timeout   time.Duration
	stats     counters
	audit     chan AuditRecord
	engine    inspectionEngine
	api       *apipolicy.Bundle
	lifetime  context.Context
	stop      context.CancelFunc
}

type requestState struct {
	operation  *apipolicy.Operation
	buffered   int64
	policy     *policy.Compiled
	event      policy.Event
	client     string
	inspection inspectionTransaction
}
type stateKey struct{}
type rejection struct{ status int }

func (e rejection) Error() string { return http.StatusText(e.status) }

func New(c Config, p *policy.Compiled) (*Firewall, error) {
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("initial policy required")
	}
	if c.MaxBufferedBytes == 0 {
		c.MaxBufferedBytes = firewalltransport.DefaultMaxBufferedBytes
	}
	c.TrustedProxyCIDRs = append([]string(nil), c.TrustedProxyCIDRs...)
	c.AllowedHosts = append([]string(nil), c.AllowedHosts...)
	f := &Firewall{cfg: c, slots: make(chan struct{}, c.MaxConcurrent), audit: make(chan AuditRecord, 256)}
	f.buffers, _ = firewalltransport.NewBufferBudget(c.MaxBufferedBytes)
	if c.DescriptorPath != "" {
		var err error
		f.api, err = apipolicy.Load(c.BootstrapDir, c.DescriptorPath, c.DescriptorSHA256)
		if err != nil {
			return nil, err
		}
	}
	f.lifetime, f.stop = context.WithCancel(context.Background())
	var err error
	f.engine, err = newInspectionEngine(c)
	if err != nil {
		return nil, err
	}
	f.current.Store(p)
	f.timeout, _ = time.ParseDuration(c.BodyTimeout)
	for _, s := range c.TrustedProxyCIDRs {
		n, _ := netip.ParsePrefix(s)
		f.trusted = append(f.trusted, n)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.UpstreamServerName}
	if c.UpstreamCA != "" {
		pem, err := os.ReadFile(c.UpstreamCA)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("upstreamCA contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	f.transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: f.timeout, IdleConnTimeout: 90 * time.Second, MaxIdleConns: c.MaxConcurrent, MaxIdleConnsPerHost: c.MaxConcurrent, MaxConnsPerHost: c.MaxConcurrent, MaxResponseHeaderBytes: maxInspectionHeaderBytes, DisableCompression: true}
	u, _ := url.Parse(c.Upstream)
	f.proxy = &httputil.ReverseProxy{Transport: headerDeadlineTransport{base: f.transport, timeout: f.timeout}, Rewrite: func(pr *httputil.ProxyRequest) {
		s := pr.In.Context().Value(stateKey{}).(*requestState)
		pr.SetURL(u)
		pr.Out.Host = pr.In.Host
		stripForwarding(pr.Out.Header)
		pr.Out.Header.Set("X-Forwarded-For", s.client)
		pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		proto := "http"
		if pr.In.TLS != nil {
			proto = "https"
		}
		pr.Out.Header.Set("X-Forwarded-Proto", proto)
	}, ModifyResponse: f.inspectResponse, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		status := http.StatusBadGateway
		var reject rejection
		if errors.As(err, &reject) {
			status = reject.status
		}
		f.reject(w, r, status)
	}}
	return f, nil
}

func (f *Firewall) SetPolicy(p *policy.Compiled) {
	if p != nil {
		f.current.Store(p)
	}
}
func (f *Firewall) Policy() *policy.Compiled { return f.current.Load() }
func (f *Firewall) SetDraining(v bool) {
	if v || f.lifetime.Err() == nil {
		f.draining.Store(v)
	}
}
func (f *Firewall) Close() error {
	f.SetDraining(true)
	f.stop()
	f.transport.CloseIdleConnections()
	return nil
}

func stripForwarding(h http.Header) {
	for k := range h {
		l := strings.ToLower(k)
		if l == "forwarded" || l == "x-real-ip" || strings.HasPrefix(l, "x-forwarded-") || l == "proxy-authorization" || l == "proxy-connection" {
			delete(h, k)
		}
	}
}

func stripBodyValidators(h http.Header) {
	for _, key := range []string{"Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
		h.Del(key)
	}
}

func (f *Firewall) clientIP(r *http.Request) (string, error) {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("invalid peer")
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return "", err
	}
	ip = ip.Unmap()
	trusted := func(ip netip.Addr) bool {
		for _, n := range f.trusted {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	if trusted(ip) {
		parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(parts) - 1; i >= 0 && trusted(ip); i-- {
			if strings.TrimSpace(parts[i]) == "" {
				if len(parts) == 1 {
					break
				}
				return "", errors.New("empty forwarded address")
			}
			ip, err = netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				return "", err
			}
			ip = ip.Unmap()
		}
	}
	return ip.String(), nil
}

func (f *Firewall) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.startServing()
	f.stats.requests.Add(1)
	if f.draining.Load() || f.lifetime.Err() != nil {
		f.reject(w, r, 503)
		return
	}
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	default:
		f.reject(w, r, 503)
		return
	}
	p := f.Policy()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(f.lifetime, cancel)
	defer func() { stop(); cancel() }()
	r = r.WithContext(ctx)
	for _, field := range []string{r.Method, r.Host, r.URL.Path, r.URL.RawQuery} {
		if len(field) > maxInspectionFieldBytes {
			f.reject(w, r, 414)
			return
		}
	}
	if !boundedInspectionHeaders(r.Header) {
		f.reject(w, r, 431)
		return
	}
	if !validQuery(r.URL.RawQuery) {
		f.reject(w, r, 400)
		return
	}
	for _, name := range []string{"Content-Type", "Content-Encoding", "Content-Length", "Authorization"} {
		if len(r.Header.Values(name)) > 1 {
			f.reject(w, r, 400)
			return
		}
	}
	if len(f.cfg.AllowedHosts) > 0 {
		found := false
		for _, h := range f.cfg.AllowedHosts {
			if strings.EqualFold(h, r.Host) {
				found = true
			}
		}
		if !found {
			f.reject(w, r, 421)
			return
		}
	}
	client, err := f.clientIP(r)
	if err != nil {
		f.reject(w, r, 400)
		return
	}
	if len(client) > maxInspectionFieldBytes {
		f.reject(w, r, 400)
		return
	}
	if r.ContentLength > f.cfg.MaxBodyBytes {
		f.reject(w, r, 413)
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(f.timeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		f.reject(w, r, 503)
		return
	}
	// Closing the body also bounds synthetic handlers whose ResponseWriter has no deadline support.
	originalBody := r.Body
	if originalBody == nil {
		originalBody = http.NoBody
	}
	canceledRead := make(chan struct{})
	stopReadCancel := context.AfterFunc(ctx, func() {
		_ = controller.SetReadDeadline(time.Now())
		_ = originalBody.Close()
		close(canceledRead)
	})
	var expired atomic.Bool
	timer := time.AfterFunc(f.timeout, func() {
		expired.Store(true)
		if originalBody != nil {
			_ = originalBody.Close()
		}
	})
	var body *bodyStore
	body, err = spoolBodyBudget(originalBody, r.Header, f.cfg.MaxBodyBytes, r.ContentLength, f.buffers)
	if body != nil {
		defer body.Close()
	}
	_ = originalBody.Close()
	timer.Stop()
	if !stopReadCancel() {
		<-canceledRead
	}
	_ = controller.SetReadDeadline(time.Time{})
	if expired.Load() {
		f.reject(w, r, 408)
		return
	}
	if err != nil {
		status := 400
		var reject rejection
		if errors.As(err, &reject) {
			status = reject.status
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			status = 408
		}
		f.reject(w, r, status)
		return
	}
	if ctx.Err() != nil {
		f.reject(w, r, 503)
		return
	}
	var operation *apipolicy.Operation
	if f.api != nil {
		operation, err = f.api.Resolve(r.Method, r.URL.Path)
		if err != nil {
			f.reject(w, r, 403)
			return
		}
		if operation != nil {
			if body.size > apipolicy.MaxBytes {
				f.reject(w, r, 413)
				return
			}
			if !f.buffers.Acquire(apiValidationCharge) {
				f.reject(w, r, 503)
				return
			}
			err = operation.ValidateRequest(r, body.reader())
			f.buffers.Release(apiValidationCharge)
			if err != nil {
				f.reject(w, r, 403)
				return
			}
		}
	}
	if err := validatePayloadReader(r, body.reader(), body.size); err != nil {
		var reject rejection
		if errors.As(err, &reject) {
			f.reject(w, r, reject.status)
		} else {
			f.reject(w, r, 400)
		}
		return
	}
	r = r.Clone(r.Context())
	if r.Header.Get("Content-Encoding") != "" {
		stripBodyValidators(r.Header)
	}
	r.Header.Del("Content-Encoding")
	r.Header.Del("Content-Length")
	r.Header.Del("Expect")
	r.Header.Del("Trailer")
	r.Trailer = nil
	r.TransferEncoding = nil
	r.GetBody = nil
	r.ContentLength = body.size
	if body.size == 0 {
		r.Body = http.NoBody
	} else {
		r.Body = body.view()
		defer r.Body.Close()
	}
	stripForwarding(r.Header)
	projection, releaseProjection, err := nativeProjection(p, "request", body)
	defer releaseProjection()
	if err != nil {
		status := 503
		var reject rejection
		if errors.As(err, &reject) {
			status = reject.status
		}
		f.reject(w, r, status)
		return
	}
	e := policy.Event{Protocol: "http", Method: r.Method, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery, ClientIP: client, Headers: r.Header.Clone(), Body: projection, Phase: "request"}
	s := &requestState{policy: p, event: e, client: client, operation: operation}
	defer func() {
		if s.inspection != nil {
			_ = s.inspection.Close()
		}
		if s.buffered > 0 {
			f.buffers.Release(s.buffered)
		}
	}()
	if status := f.evaluate(r.Context(), s.policy, e); status != 0 {
		f.reject(w, r, status)
		return
	}
	if f.engine != nil {
		charge := body.size + bodyMemoryBytes
		if !f.buffers.Acquire(charge) {
			f.reject(w, r, 503)
			return
		}
		s.buffered += charge
		var status int
		s.inspection, status, err = f.engine.request(r, body.reader(), client, s.policy.Bundle().Mode == "monitor")
		if status = f.inspectionDecision(s.policy, "request", status, err); status != 0 {
			f.reject(w, r, status)
			return
		}
	}
	s.event.Body = ""
	releaseProjection()
	pw := &finalResponseWriter{ResponseWriter: w, ctx: r.Context()}
	defer pw.finish()
	f.proxy.ServeHTTP(pw, r.WithContext(context.WithValue(r.Context(), stateKey{}, s)))
}

func boundedInspectionHeaders(h http.Header) bool {
	if len(h) > 128 {
		return false
	}
	bytes, values := 0, 0
	for key, vs := range h {
		if len(key) > 1024 {
			return false
		}
		bytes += len(key)
		values += len(vs)
		if values > 1024 || bytes > maxInspectionHeaderBytes {
			return false
		}
		for _, value := range vs {
			if len(value) > maxInspectionHeaderBytes-bytes {
				return false
			}
			bytes += len(value)
		}
	}
	return true
}

func validQuery(query string) bool {
	hex := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
	for i := 0; i < len(query); i++ {
		if query[i] == ';' {
			return false
		}
		if query[i] == '%' {
			if i+2 >= len(query) || !hex(query[i+1]) || !hex(query[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

// ReverseProxy otherwise forwards origin 103 headers before ModifyResponse can deny.
type finalResponseWriter struct {
	http.ResponseWriter
	ctx  context.Context
	conn net.Conn
	stop func() bool
}

func (w finalResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != 101 {
		return
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w finalResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *finalResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.conn = c
		w.stop = context.AfterFunc(w.ctx, func() { _ = c.Close() })
	}
	return c, rw, err
}
func (w *finalResponseWriter) finish() {
	if w.stop != nil {
		w.stop()
	}
	if w.conn != nil {
		_ = w.conn.Close()
	}
}

type headerDeadlineTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (t headerDeadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(r.Context())
	timer := time.AfterFunc(t.timeout, cancel)
	resp, err := t.base.RoundTrip(r.Clone(ctx))
	timer.Stop()
	if err != nil {
		cancel()
		return nil, err
	}
	if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
		resp.Body = &cancelReadWriteBody{ReadWriteCloser: rw, cancel: cancel}
	} else {
		resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

type cancelReadWriteBody struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
}

func (b *cancelReadWriteBody) Close() error { err := b.ReadWriteCloser.Close(); b.cancel(); return err }

func (f *Firewall) evaluate(ctx context.Context, p *policy.Compiled, e policy.Event) int {
	var d policy.Decision
	var err error
	if hook := f.evaluator.Load(); hook != nil {
		d, err = hook.evaluate(ctx, p, e)
	} else {
		d, err = p.Evaluate(e)
	}
	if err != nil {
		f.stats.errors.Add(1)
		f.record(AuditRecord{Phase: e.Phase, Verdict: "error", Status: 503})
		// A broker failure accompanying an enforcing deny cannot replace that deny.
		if (d.Verdict != "deny" && d.Verdict != "block") || d.Monitor {
			return 503
		}
	}
	f.record(AuditRecord{Phase: e.Phase, Verdict: d.Verdict, Status: d.Status, RuleID: d.RuleID, Revision: d.Revision, Monitor: d.Monitor})
	if d.Verdict == "would-deny" && d.Monitor {
		f.stats.wouldDeny.Add(1)
		return 0
	}
	if d.Verdict == "deny" || d.Verdict == "block" {
		if d.Monitor {
			f.stats.wouldDeny.Add(1)
			return 0
		}
		f.stats.denied.Add(1)
		if d.Status < 400 || d.Status > 599 {
			return 403
		}
		return d.Status
	}
	if d.Verdict != "allow" {
		f.stats.errors.Add(1)
		return 503
	}
	return 0
}

func (f *Firewall) inspectResponse(resp *http.Response) error {
	if !boundedInspectionHeaders(resp.Header) {
		_ = resp.Body.Close()
		return rejection{502}
	}
	s := resp.Request.Context().Value(stateKey{}).(*requestState)
	e := s.event
	e.Phase = "response"
	e.Body = ""
	e.Status = resp.StatusCode
	e.Headers = resp.Header.Clone()
	var inspected *bodyStore
	apiResponse := f.cfg.APIValidateResponse && s.operation != nil
	inspectBody := f.cfg.InspectResponse || apiResponse
	if inspectBody && resp.StatusCode == 101 {
		_ = resp.Body.Close()
		return rejection{502}
	}
	if inspectBody && resp.Request.Method != http.MethodHead && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		if resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Range") != "" {
			_ = resp.Body.Close()
			return rejection{502}
		}
		// A bounded read also needs a wall-clock bound for streaming origins.
		originalBody := resp.Body
		var expired atomic.Bool
		timer := time.AfterFunc(f.timeout, func() { expired.Store(true); _ = originalBody.Close() })
		b, err := spoolBodyBudget(originalBody, resp.Header, f.cfg.MaxResponseBytes, resp.ContentLength, f.buffers)
		if b != nil {
			defer b.Close()
		}
		timer.Stop()
		_ = originalBody.Close()
		if err != nil || expired.Load() {
			var reject rejection
			if !expired.Load() && errors.As(err, &reject) && reject.status == 503 {
				return rejection{503}
			}
			return rejection{502}
		}
		if resp.Header.Get("Content-Encoding") != "" {
			stripBodyValidators(resp.Header)
			resp.Header.Del("ETag")
			resp.Header.Del("Accept-Ranges")
		}
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.Header.Del("Trailer")
		resp.Trailer = nil
		resp.TransferEncoding = nil
		resp.ContentLength = b.size
		resp.Body = b.view()
		var releaseProjection func()
		e.Body, releaseProjection, err = nativeProjection(s.policy, "response", b)
		defer releaseProjection()
		if err != nil {
			_ = resp.Body.Close()
			var reject rejection
			if errors.As(err, &reject) && reject.status == 503 {
				return rejection{503}
			}
			return rejection{502}
		}
		inspected = b
		e.Headers = resp.Header.Clone()
	}
	if apiResponse {
		var reader io.Reader = strings.NewReader("")
		if inspected != nil {
			reader = inspected.reader()
			if inspected.size > apipolicy.MaxBytes {
				_ = resp.Body.Close()
				return rejection{502}
			}
		}
		if !f.buffers.Acquire(apiValidationCharge) {
			_ = resp.Body.Close()
			return rejection{503}
		}
		err := s.operation.ValidateResponse(resp.StatusCode, resp.Header, reader)
		f.buffers.Release(apiValidationCharge)
		if err != nil {
			_ = resp.Body.Close()
			return rejection{502}
		}
	}
	if status := f.evaluate(resp.Request.Context(), s.policy, e); status != 0 {
		_ = resp.Body.Close()
		return rejection{status}
	}
	if s.inspection != nil {
		var reader io.Reader = strings.NewReader("")
		if inspected != nil {
			if !f.buffers.Acquire(inspected.size) {
				_ = resp.Body.Close()
				return rejection{503}
			}
			s.buffered += inspected.size
			reader = inspected.reader()
		}
		status, err := s.inspection.response(resp, reader, f.cfg.InspectResponse)
		if status = f.inspectionDecision(s.policy, "response", status, err); status != 0 {
			_ = resp.Body.Close()
			return rejection{status}
		}
	}
	return nil
}

func (f *Firewall) reject(w http.ResponseWriter, r *http.Request, status int) {
	f.stats.rejected.Add(1)
	// Do not let net/http drain an uninspected HTTP/1 body before sending a rejection.
	if r.ProtoMajor < 2 {
		w.Header().Set("Connection", "close")
	}
	http.Error(w, http.StatusText(status), status)
}
