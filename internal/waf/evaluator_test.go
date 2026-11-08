package waf

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/responseactions"
)

type hookContextKey struct{}

func TestEvaluatorPinsRevisionAtAdmissionAndCarriesContext(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "allowed")
	}))
	defer origin.Close()
	p := compiled(t, "enforce", "request", "")
	f := firewall(t, config(origin.URL), p)
	var seen []string
	if err := f.SetEvaluator(func(ctx context.Context, snapshot *policy.Compiled, e policy.Event) (policy.Decision, error) {
		if ctx.Value(hookContextKey{}) != "tenant-a" || snapshot != p {
			t.Errorf("hook lost request attribution/revision: %v %p", ctx.Value(hookContextKey{}), snapshot)
		}
		seen = append(seen, e.Phase)
		return snapshot.Evaluate(e)
	}); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	started := make(chan struct{})
	body := &admissionBody{ReadCloser: reader, started: started}
	r := httptest.NewRequest("POST", "http://route.example/", body)
	r = r.WithContext(context.WithValue(r.Context(), hookContextKey{}, "tenant-a"))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); f.ServeHTTP(w, r) }()
	<-started
	f.SetPolicy(compiled(t, "enforce", "request", "true"))
	_, _ = io.WriteString(writer, "safe")
	_ = writer.Close()
	<-done
	if w.Code != 200 || strings.Join(seen, ",") != "request,response" {
		t.Fatalf("reload changed an admitted request: %d %v", w.Code, seen)
	}
}

type admissionBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (b *admissionBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}

func TestEvaluatorIsBootstrapOnly(t *testing.T) {
	hook := func(_ context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
		return p.Evaluate(e)
	}
	f := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", "true"))
	if f.SetEvaluator(nil) == nil {
		t.Fatal("nil evaluator accepted")
	}
	if err := f.SetEvaluator(hook); err != nil {
		t.Fatal(err)
	}
	if f.SetEvaluator(hook) == nil {
		t.Fatal("evaluator replaced")
	}
	g := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", "true"))
	_ = call(g, "")
	if g.SetEvaluator(hook) == nil {
		t.Fatal("evaluator installed after serving")
	}
}

func effectPolicy(t *testing.T, mode, expression string) *policy.Compiled {
	t.Helper()
	p, err := policy.CompileWithOptions(policy.Bundle{Version: "v1", ID: "effects", Mode: mode, Default: "allow", Rules: []policy.Rule{{ID: "deny-effects", Phase: "request", Expression: expression, Action: "deny", Status: 451, Effects: []policy.Effect{{Kind: "block_source", Target: "client", Scope: "edge", Duration: "1m"}}}}}, policy.CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEvaluatorPreservesDenyWhenBrokerUnavailable(t *testing.T) {
	p := effectPolicy(t, "enforce", "true")
	f := firewall(t, config("http://127.0.0.1:1"), p)
	if err := f.SetEvaluator(func(_ context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
		return (&responseactions.Evaluator{Policy: p}).Evaluate(e)
	}); err != nil {
		t.Fatal(err)
	}
	w := call(f, "")
	if w.Code != 451 || f.stats.denied.Load() != 1 || f.stats.errors.Load() != 1 {
		t.Fatalf("broker error replaced native deny: status=%d denied=%d errors=%d", w.Code, f.stats.denied.Load(), f.stats.errors.Load())
	}
}

func TestMessageHandshakePreservesEvaluatorDenyStatus(t *testing.T) {
	for _, protocol := range []string{"grpc", "websocket"} {
		t.Run(protocol, func(t *testing.T) {
			f := firewall(t, config("http://127.0.0.1:1"), effectPolicy(t, "enforce", "true"))
			if err := f.SetEvaluator(func(_ context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
				return (&responseactions.Evaluator{Policy: p}).Evaluate(e)
			}); err != nil {
				t.Fatal(err)
			}
			h, err := f.MessageHandler(true, true)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "https://route.example/service/method", nil)
			if protocol == "grpc" {
				r.ProtoMajor = 2
				r.Header.Set("Content-Type", "application/grpc")
			} else {
				r.Method = "GET"
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "Upgrade")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 451 {
				t.Fatalf("%s handshake replaced winning deny: %d", protocol, w.Code)
			}
			if f.SetEvaluator(func(context.Context, *policy.Compiled, policy.Event) (policy.Decision, error) {
				return policy.Decision{}, nil
			}) == nil {
				t.Fatal("message serving did not freeze evaluator")
			}
		})
	}
}

func TestEvaluatorErrorWithoutDenyFailsClosed(t *testing.T) {
	f := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", ""))
	if err := f.SetEvaluator(func(context.Context, *policy.Compiled, policy.Event) (policy.Decision, error) {
		return policy.Decision{Verdict: "allow"}, errors.New("shared store unavailable")
	}); err != nil {
		t.Fatal(err)
	}
	if w := call(f, ""); w.Code != 503 {
		t.Fatalf("hook failure allowed request: %d", w.Code)
	}
}
