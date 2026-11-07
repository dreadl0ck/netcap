package waf

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/policy"
)

// MessageHandler explicitly bypasses full-body buffering only for enabled modes.
// Each connection/RPC pins one policy revision and is canceled by Firewall.Close.
func (f *Firewall) MessageHandler(websocket, grpc bool) (http.Handler, error) {
	if f.router != nil {
		return nil, errors.New("message adapters require a single-origin binding")
	}
	u, _ := url.Parse(f.cfg.Upstream)
	c := firewalltransport.Config{WebSocket: websocket, GRPC: grpc, Upstream: u, Transport: f.transport, MessageTimeout: f.timeout, MaxConcurrent: f.cfg.MaxConcurrent, Context: f.lifetime, Budget: f.buffers, ByteEvents: true}
	c.Begin = func(r *http.Request) firewalltransport.InspectFunc {
		p := f.Policy()
		client, err := f.clientIP(r)
		if err != nil || f.draining.Load() || !validQuery(r.URL.RawQuery) || !boundedInspectionHeaders(r.Header) || argumentCount(r.URL.RawQuery) > maxArguments {
			return nil
		}
		if len(f.cfg.AllowedHosts) > 0 {
			allowed := false
			for _, host := range f.cfg.AllowedHosts {
				if strings.EqualFold(host, r.Host) {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil
			}
		}
		for _, name := range []string{"Content-Type", "Content-Encoding", "Content-Length", "Authorization"} {
			if len(r.Header.Values(name)) > 1 {
				return nil
			}
		}
		select {
		case f.slots <- struct{}{}:
		default:
			return nil
		}
		f.stats.requests.Add(1)
		return func(ctx context.Context, m firewalltransport.Event) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var projection string
			if policyRequiresBody(p, m.Phase) {
				charge := int64(len(m.Payload))
				if !f.buffers.Acquire(charge) {
					return firewalltransport.ErrBufferCapacity
				}
				defer f.buffers.Release(charge)
				projection = string(m.Payload)
			}
			e := policy.Event{Protocol: m.Protocol, Phase: m.Phase, Method: m.Method, Host: m.Host, Path: m.Path, RawQuery: m.RawQuery, ClientIP: client, Body: projection, Headers: m.Headers, Attributes: m.Attributes, Status: m.Status}
			if status := f.evaluate(ctx, p, e); status != 0 {
				return firewalltransport.Rejection{Status: status}
			}
			if f.engine != nil {
				charge := int64(len(m.Payload)) + bodyMemoryBytes
				if !f.buffers.Acquire(charge) {
					return firewalltransport.ErrBufferCapacity
				}
				defer f.buffers.Release(charge)
				request := r.Clone(ctx)
				request.Header.Del("Content-Length")
				request.Header.Del("Content-Encoding")
				request.Header.Del("Sec-WebSocket-Extensions")
				request.ContentLength = int64(len(m.Payload))
				body := m.Payload
				if m.Phase == "response" {
					body = nil
					request.ContentLength = 0
				}
				tx, status, err := f.engine.request(request, bytes.NewReader(body), client, p.Bundle().Mode == "monitor")
				if tx != nil {
					defer tx.Close()
				}
				if status = f.inspectionDecision(p, "request", status, err); status != 0 {
					return firewalltransport.Rejection{Status: status}
				}
				if m.Phase == "response" && tx != nil {
					resp := &http.Response{StatusCode: m.Status, Proto: r.Proto, Header: m.Headers, ContentLength: int64(len(m.Payload))}
					status, err = tx.response(resp, bytes.NewReader(m.Payload), true)
					if status = f.inspectionDecision(p, "response", status, err); status != 0 {
						return firewalltransport.Rejection{Status: status}
					}
				}
			}
			return nil
		}
	}
	c.End = func(*http.Request) { <-f.slots }
	handler, err := firewalltransport.New(c, f, nil)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.startServing(); handler.ServeHTTP(w, r) }), nil
}
