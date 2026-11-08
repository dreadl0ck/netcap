package firewalltransport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrDenied = errors.New("message denied")
var ErrFraming = errors.New("invalid message framing")

type grpcReader struct {
	readMu sync.Mutex
	mu     sync.Mutex
	closed bool
	budget *BufferBudget
	charge int64
	eof    bool
	io.ReadCloser
	ctx      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	encoding string
	inspect  func([]byte, bool, uint64) error
	pending  *bytes.Reader
	index    uint64
	onEOF    func() error
}

func (g *grpcReader) Read(p []byte) (int, error) {
	g.readMu.Lock()
	defer g.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if g.pending != nil {
		n, err := g.pending.Read(p)
		if g.pending.Len() == 0 {
			g.releasePending()
		}
		g.mu.Unlock()
		return n, err
	}
	g.mu.Unlock()
	if g.eof {
		return 0, io.EOF
	}
	if err := g.ctx.Err(); err != nil {
		return 0, err
	}
	// A partial header or payload cannot hold an upstream stream indefinitely.
	timer := time.AfterFunc(g.timeout, func() { g.cancel(); _ = g.ReadCloser.Close() })
	defer timer.Stop()
	var head [5]byte
	if _, err := io.ReadFull(g.ReadCloser, head[:]); err != nil {
		if err == io.EOF && g.onEOF != nil {
			if trailerErr := g.onEOF(); trailerErr != nil {
				g.cancel()
				if errors.Is(trailerErr, ErrBufferCapacity) {
					return 0, ErrBufferCapacity
				}
				if errors.Is(trailerErr, ErrDenied) {
					return 0, trailerErr
				}
				return 0, ErrDenied
			}
		}
		if err == io.EOF {
			g.eof = true
		} else {
			g.cancel()
		}
		return 0, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if head[0] > 1 || n > MaxMessageBytes {
		g.cancel()
		return 0, ErrFraming
	}
	charge := int64(5) + int64(n)
	if g.budget != nil {
		if !g.budget.Acquire(charge) {
			g.cancel()
			return 0, ErrBufferCapacity
		}
		defer func() {
			if charge > 0 {
				g.budget.Release(charge)
			}
		}()
	}
	wire := make([]byte, 5+int(n))
	copy(wire, head[:])
	if _, err := io.ReadFull(g.ReadCloser, wire[5:]); err != nil {
		g.cancel()
		return 0, err
	}
	data := wire[5:]
	if head[0] == 1 {
		if g.budget != nil {
			if !g.budget.Acquire(MaxMessageBytes + 1) {
				g.cancel()
				return 0, ErrBufferCapacity
			}
			defer g.budget.Release(MaxMessageBytes + 1)
		}
		if g.encoding != "gzip" {
			g.cancel()
			return 0, ErrFraming
		}
		z, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			g.cancel()
			return 0, ErrFraming
		}
		data, err = readExpandedMessage(z)
		_ = z.Close()
		if err != nil || len(data) > MaxMessageBytes {
			g.cancel()
			return 0, ErrFraming
		}
	}
	g.index++
	if err := g.inspect(data, head[0] == 1, g.index); err != nil {
		g.cancel()
		if errors.Is(err, ErrBufferCapacity) {
			return 0, ErrBufferCapacity
		}
		if errors.Is(err, ErrDenied) {
			return 0, err
		}
		return 0, ErrDenied
	}
	if err := g.ctx.Err(); err != nil {
		return 0, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, io.ErrClosedPipe
	}
	g.pending = bytes.NewReader(wire)
	g.charge = charge
	charge = 0
	read, err := g.pending.Read(p)
	if g.pending.Len() == 0 {
		g.releasePending()
	}
	return read, err
}

// The caller reserves MaxMessageBytes+1 before allocating this exact-capacity buffer.
func readExpandedMessage(r io.Reader) ([]byte, error) {
	data := make([]byte, MaxMessageBytes+1)
	size, emptyReads := 0, 0
	for size < len(data) {
		n, err := r.Read(data[size:])
		size += n
		if err == io.EOF {
			return data[:size], nil
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			emptyReads++
			if emptyReads == 100 {
				return nil, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
	return data, nil
}

// Caller holds mu. Active reads own their temporary reservation until they return.
func (g *grpcReader) releasePending() {
	g.pending = nil
	if g.budget != nil {
		g.budget.Release(g.charge)
	}
	g.charge = 0
}
func (g *grpcReader) Close() error {
	g.mu.Lock()
	g.closed = true
	g.releasePending()
	g.mu.Unlock()
	return g.ReadCloser.Close()
}

func grpcEncoding(h http.Header) (string, error) {
	if len(h.Values("Grpc-Encoding")) > 1 {
		return "", ErrFraming
	}
	e := strings.TrimSpace(strings.ToLower(h.Get("Grpc-Encoding")))
	if e != "" && e != "identity" && e != "gzip" {
		return "", ErrFraming
	}
	return e, nil
}

func grpcRejectionCode(err error) string {
	if errors.Is(err, ErrBufferCapacity) || inspectionStatus(err) == 429 {
		return "8"
	}
	if inspectionStatus(err) == 503 {
		return "14"
	}
	if errors.Is(err, ErrDenied) {
		return "7"
	}
	return "13"
}

func (h *Handler) grpc(w http.ResponseWriter, r, source *http.Request) {
	if !h.cfg.Budget.Acquire(32 << 10) {
		http.Error(w, "inspection capacity exhausted", 503)
		return
	}
	defer h.cfg.Budget.Release(32 << 10)
	if (r.ProtoMajor != 2 && !(r.ProtoMajor == 3 && HTTP3Available && h.cfg.HTTP3MessageProfile)) || r.Method != http.MethodPost {
		http.Error(w, "streaming gRPC requires HTTP/2 POST or enabled HTTP/3 message profile", 400)
		return
	}
	if r.Header.Get("Content-Encoding") != "" || len(r.Header.Values("Content-Type")) != 1 {
		http.Error(w, "HTTP content coding unsupported for gRPC", 415)
		return
	}
	encoding, err := grpcEncoding(r.Header)
	if err != nil {
		http.Error(w, "unsupported gRPC encoding", 415)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	out := h.outbound(r, ctx)
	// HTTP/3 ingress carries the same bounded message envelope to an HTTP/2
	// origin. This profile does not advertise standard gRPC-over-HTTP/3 support.
	out.Proto, out.ProtoMajor, out.ProtoMinor = "HTTP/2.0", 2, 0
	out.Header.Del("Content-Length")
	out.Header.Set("Grpc-Accept-Encoding", "identity,gzip")
	out.ContentLength = -1
	out.GetBody = nil
	out.Trailer = r.Trailer.Clone()
	var headerMu sync.Mutex
	var headerTimer *time.Timer
	headersReturned := false
	inspect := func(phase string, headers http.Header, status int) func([]byte, bool, uint64) error {
		return func(data []byte, compressed bool, index uint64) error {
			charge := int64(len(data))
			if h.cfg.ByteEvents {
				charge = 0
			}
			if !h.cfg.Budget.Acquire(charge) {
				return ErrBufferCapacity
			}
			defer h.cfg.Budget.Release(charge)
			e := h.messageEvent(r, "grpc", phase, data, status)
			e.Headers = headers.Clone()
			e.Attributes["message.index"] = strconv.FormatUint(index, 10)
			e.Attributes["inspection.kind"] = "message"
			e.Attributes["grpc.compressed"] = strconv.FormatBool(compressed)
			e.Attributes["http.message_profile"] = "grpc-h2"
			if r.ProtoMajor == 3 {
				e.Attributes["http.message_profile"] = "grpc-envelope-h3-to-h2"
			}
			return h.inspect(ctx, e)
		}
	}
	requestBody := r.Body
	if requestBody == nil {
		requestBody = http.NoBody
	}
	out.Body = &grpcReader{ReadCloser: requestBody, ctx: ctx, cancel: cancel, timeout: h.cfg.MessageTimeout, encoding: encoding, inspect: inspect("request", r.Header, 0), budget: h.cfg.Budget}
	out.Body.(*grpcReader).onEOF = func() error {
		trailers := source.Trailer
		if !validHeaders(trailers) {
			return ErrFraming
		}
		e := event(r, "grpc", "request", nil, 0)
		e.Headers = trailers.Clone()
		e.Attributes["grpc.trailers"] = "true"
		e.Attributes["inspection.kind"] = "trailers"
		if err := h.inspect(ctx, e); err != nil {
			return err
		}
		if out.Trailer == nil {
			out.Trailer = make(http.Header)
		}
		for key, values := range trailers {
			out.Trailer[key] = append([]string(nil), values...)
		}
		headerMu.Lock()
		if !headersReturned && headerTimer == nil {
			headerTimer = time.AfterFunc(h.cfg.MessageTimeout, cancel)
		}
		headerMu.Unlock()
		return nil
	}
	defer out.Body.Close()
	stop := context.AfterFunc(ctx, func() { _ = requestBody.Close() })
	defer stop()
	// HTTP/2 and quic-go's HTTP/3 handler are duplex without EnableFullDuplex.
	resp, err := h.cfg.Transport.RoundTrip(out)
	headerMu.Lock()
	headersReturned = true
	if headerTimer != nil {
		headerTimer.Stop()
	}
	headerMu.Unlock()
	if err != nil {
		http.Error(w, "gRPC upstream failed", 502)
		return
	}
	defer resp.Body.Close()
	stopResponse := context.AfterFunc(ctx, func() { _ = resp.Body.Close() })
	defer stopResponse()
	if resp.ProtoMajor != 2 || !validHeaders(resp.Header) || resp.Header.Get("Content-Encoding") != "" || len(resp.Header.Values("Content-Type")) != 1 || !grpcMediaType(resp.Header.Get("Content-Type")) {
		http.Error(w, "invalid gRPC upstream", 502)
		return
	}
	encoding, err = grpcEncoding(resp.Header)
	if err != nil {
		http.Error(w, "unsupported upstream gRPC encoding", 502)
		return
	}
	e := event(r, "grpc", "response", nil, resp.StatusCode)
	e.Headers = resp.Header.Clone()
	if err := h.inspect(ctx, e); err != nil {
		http.Error(w, "response denied", inspectionStatus(err))
		return
	}
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Grpc-Accept-Encoding", "identity,gzip")
	w.Header().Del("Content-Length")
	w.Header().Add("Trailer", "Grpc-Status, Grpc-Message")
	for name := range resp.Trailer {
		if name != "Grpc-Status" && name != "Grpc-Message" {
			w.Header().Add("Trailer", name)
		}
	}
	w.WriteHeader(resp.StatusCode)
	g := &grpcReader{ReadCloser: resp.Body, ctx: ctx, cancel: cancel, timeout: h.cfg.MessageTimeout, encoding: encoding, inspect: inspect("response", resp.Header, resp.StatusCode), budget: h.cfg.Budget}
	defer g.Close()
	buf := make([]byte, 32<<10)
	for {
		n, readErr := g.Read(buf)
		if n > 0 {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.cfg.MessageTimeout))
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			w.Header().Set("Grpc-Status", grpcRejectionCode(readErr))
			w.Header().Set("Grpc-Message", "message inspection rejected stream")
			return
		}
	}
	if !validHeaders(resp.Trailer) {
		w.Header().Set("Grpc-Status", "13")
		return
	}
	trailerEvent := event(r, "grpc", "response", nil, resp.StatusCode)
	trailerEvent.Headers = resp.Trailer.Clone()
	trailerEvent.Attributes["grpc.trailers"] = "true"
	trailerEvent.Attributes["inspection.kind"] = "trailers"
	if err := h.inspect(ctx, trailerEvent); err != nil {
		w.Header().Set("Grpc-Status", grpcRejectionCode(err))
		return
	}
	for k, v := range resp.Trailer {
		w.Header()[http.TrailerPrefix+k] = v
	}
}
