package protocoltest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loopback(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}
func lineExchange(address string, steps ...Step) Exchange {
	return Exchange{Version: 1, Network: "tcp", Address: address, Framing: Framing{Kind: "delimiter", Delimiter: []byte("\n"), MaxBytes: 128}, MaxTotalBytes: 1024, TimeoutMilliseconds: 2000, Steps: steps}
}

func fixtureMetadata() ExperimentMetadata {
	return ExperimentMetadata{Version: 1, TargetVersion: "loopback-fixture-v1", Reset: ResetSpec{Mode: "connection", Description: "fixture state and variables are scoped to a new connection"}}
}

func TestServeOneStateCaptureResetAndNegativeControl(t *testing.T) {
	for _, request := range []string{"fresh-one\n", "fresh-two\n", "wrong\n"} {
		l := loopback(t)
		spec := lineExchange(l.Addr().String(), Step{Receive: true, Contains: []byte("fresh-"), CaptureVariable: "request", CaptureLength: len(request)}, Step{SendVariable: "request"})
		done := make(chan Result, 1)
		go func() { r, _ := ServeOne(context.Background(), l, spec); done <- r }()
		r, err := Run(context.Background(), lineExchange(l.Addr().String(), Step{Send: []byte(request), Receive: true, Expect: []byte(request)}))
		server := <-done
		if request == "wrong\n" {
			if err == nil || server.Status != "error" || server.Error == "" || len(server.Observations) != 1 {
				t.Fatalf("negative control %+v %v", server, err)
			}
		} else if err != nil || r.Status != "matched" || server.Status != "matched" || string(server.Observations[1].Bytes) != request {
			t.Fatalf("state exchange %+v %+v %v", r, server, err)
		}
	}
	l := loopback(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ServeOne(ctx, l, lineExchange(l.Addr().String(), Step{Receive: true}))
	if err == nil {
		t.Fatal("canceled accept succeeded")
	}
}

func TestTwoLegTLSProxyMutatesBothDirectionsAndRejectsHostname(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"example.com", "wrong.invalid", "untrusted-front", "mtls-required"} {
		t.Run(name, func(t *testing.T) {
			config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
			if name == "mtls-required" {
				config.ClientAuth = tls.RequireAnyClientCert
			}
			upstream := tls.NewListener(loopback(t), config)
			serverDone := make(chan error, 1)
			go func() {
				c, e := upstream.Accept()
				if e != nil {
					serverDone <- e
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				b, e := lineExchange("").Framing.Read(c)
				if e == nil && string(b) != "edit\n" {
					e = errors.New("upstream did not receive mutation")
				}
				if e == nil {
					_, e = c.Write([]byte("reply\n"))
				}
				serverDone <- e
			}()
			front := loopback(t)
			spec := Proxy{Address: upstream.Addr().String(), TLS: &ProxyTLS{CertificateFile: ca, KeyFile: key, RootCAFile: ca, ServerName: name}, Framing: lineExchange("").Framing, TimeoutMilliseconds: 2000, MaxFrames: 8, MaxTotalBytes: 1024, Mutations: []Mutation{{Direction: "client", Frame: 0, Offset: 0, Delete: 4, Insert: []byte("edit")}, {Direction: "server", Frame: 0, Offset: 0, Delete: 5, Insert: []byte("changed")}}}
			if name != "wrong.invalid" {
				spec.TLS.ServerName = "example.com"
			}
			type outcome struct {
				obs []ProxyObservation
				err error
			}
			done := make(chan outcome, 1)
			go func() { o, e := ProxyOne(context.Background(), front, spec); done <- outcome{o, e} }()
			client := lineExchange(front.Addr().String(), Step{Send: []byte("send\n"), Receive: true, Expect: []byte("changed\n")})
			client.TLS = true
			client.RootCAFile = ca
			client.ServerName = "example.com"
			if name == "untrusted-front" {
				client.RootCAFile = ""
			}
			r, e := Run(context.Background(), client)
			p := <-done
			se := <-serverDone
			if name != "example.com" {
				if e == nil || p.err == nil {
					t.Fatalf("untrusted upstream accepted %+v %v", p, e)
				}
			} else {
				if e != nil || p.err != nil || se != nil || r.TLSVersion == 0 || len(p.obs) != 2 {
					t.Fatalf("TLS workflow %+v %v %v %v", p, e, se, r)
				}
				for _, o := range p.obs {
					if bytes.Equal(o.Original, o.Transmitted) || o.TLSVersion < tls.VersionTLS12 || o.TLSCipher == 0 {
						t.Fatal("missing before/after")
					}
				}
			}
		})
	}
}

func TestAccessMatrixActualMarkersAndCanonicalization(t *testing.T) {
	for _, broken := range []bool{false, true} {
		l := loopback(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 6 {
				c, e := l.Accept()
				if e != nil {
					return
				}
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				f := lineExchange("").Framing
				b, e := f.Read(c)
				if e == nil {
					parts := strings.Fields(string(b))
					response := "DENIED\n"
					if len(parts) == 2 && path.Clean(parts[1]) == "/alice/fixture" && (parts[0] == "alice" || broken) {
						response = "ALICE-ONLY-MARKER\n"
					}
					_, _ = c.Write([]byte(response))
				}
				_ = c.Close()
			}
		}()
		cases := []AccessCase{}
		for _, role := range []string{"anonymous", "alice", "bob"} {
			for _, resource := range []string{"/alice/fixture", "/alice/../alice/fixture"} {
				cases = append(cases, AccessCase{Metadata: fixtureMetadata(), Role: role, State: "read", Resource: resource, Message: "get", Allowed: role == "alice", Marker: []byte("ALICE-ONLY-MARKER"), Exchange: lineExchange(l.Addr().String(), Step{Send: []byte(role + " " + resource + "\n"), Receive: true})})
			}
		}
		results, e := RunAccess(context.Background(), cases)
		<-done
		if e != nil || len(results) != 6 {
			t.Fatal(e)
		}
		mismatches := 0
		for _, r := range results {
			if r.Status == "boundary-mismatch" {
				mismatches++
			}
			if len(r.Result.Observations) != 2 {
				t.Fatal("missing wire evidence")
			}
		}
		want := 0
		if broken {
			want = 4
		}
		if mismatches != want {
			t.Fatalf("got %d boundary mismatches want %d", mismatches, want)
		}
	}
}

func TestCorpusMinimizeLoopbackAndExternalTriage(t *testing.T) {
	seed := []byte("padding!more\n")
	a, e := MutationCorpus(seed, 64, 4096)
	if e != nil {
		t.Fatal(e)
	}
	b, e := MutationCorpus(seed, 64, 4096)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if e != nil || !bytes.Equal(ja, jb) || len(a) != 1+2*len(seed) {
		t.Fatal("non-reproducible corpus")
	}
	if _, e = MutationCorpus(seed, 1, 4096); e == nil {
		t.Fatal("budget ignored")
	}
	l := loopback(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			f := lineExchange("").Framing
			data, e := f.Read(c)
			if e == nil {
				response := "VALID\n"
				if bytes.Contains(data, []byte("!")) {
					response = "REJECTED\n"
				}
				_, _ = c.Write([]byte(response))
			}
			_ = c.Close()
		}
	}()
	oracle := func(ctx context.Context, input []byte) (bool, error) {
		input = append(bytes.TrimSuffix(input, []byte("\n")), '\n')
		r, e := Run(ctx, lineExchange(l.Addr().String(), Step{Send: input, Receive: true}))
		if e != nil {
			return false, e
		}
		return bytes.Equal(r.Observations[1].Bytes, []byte("REJECTED\n")), nil
	}
	if failed, e := oracle(context.Background(), []byte("valid")); e != nil || failed {
		t.Fatal("valid precontrol failed")
	}
	minimized, e := Minimize(context.Background(), seed, 100, oracle)
	if e != nil || !minimized.Complete || string(minimized.Input) != "!" {
		t.Fatalf("minimization %+v %v", minimized, e)
	}
	if failed, e := oracle(context.Background(), []byte("valid")); e != nil || failed {
		t.Fatal("valid postcontrol failed")
	}
	_ = l.Close()
	<-done
	artifact := filepath.Join(t.TempDir(), "stderr.txt")
	raw := []byte("fixture process exited 1; no demonstrated impact\n")
	if e = os.WriteFile(artifact, raw, 0600); e != nil {
		t.Fatal(e)
	}
	report, e := ImportTriage("process", "fixture-v1", "new connection", minimized.Input, artifact)
	if e != nil || !bytes.Equal(report.Evidence, raw) || len(report.EvidenceSHA256) != 64 || report.Classification != "external evidence; impact unverified" {
		t.Fatalf("triage %+v %v", report, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = Minimize(ctx, seed, 100, oracle); e == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestUnsupportedModesAndOracleFailures(t *testing.T) {
	l := loopback(t)
	e := lineExchange(l.Addr().String(), Step{Receive: true})
	e.Network = "udp"
	if _, err := ServeOne(context.Background(), l, e); err == nil {
		t.Fatal("UDP server silently accepted")
	}
	if _, _, err := proxyTLSConfigs(&ProxyTLS{Mode: "passthrough"}); err == nil {
		t.Fatal("ciphertext mutation silently accepted")
	}
	sentinel := errors.New("fixture unavailable")
	r, err := Minimize(context.Background(), []byte("x"), 10, func(context.Context, []byte) (bool, error) { return true, sentinel })
	if !errors.Is(err, sentinel) || r.Complete {
		t.Fatal("oracle transport error classified as reproduction")
	}
	if _, err = ImportTriage("rce", "v1", "reset", nil, "ignored"); err == nil {
		t.Fatal("unsupported classification accepted")
	}
	e.Network = "tcp"
	e.MaxTotalBytes = 1
	if _, err = RunAccess(context.Background(), []AccessCase{{Role: "a", State: "b", Resource: "c", Message: "d", Marker: []byte("x"), ResponseStep: 2, Exchange: e}}); err == nil {
		t.Fatal("invalid response selector accepted")
	}
}

func TestProxyFailedMutationAndCanceledDelayRetainOriginal(t *testing.T) {
	for _, m := range []Mutation{{Direction: "client", Offset: 100}, {Direction: "client", DelayMilliseconds: 1000}} {
		upstream := loopback(t)
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			c, e := upstream.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = lineExchange("").Framing.Read(c)
		}()
		front := loopback(t)
		done := make(chan []ProxyObservation, 1)
		go func() {
			r, _ := ProxyOne(context.Background(), front, Proxy{Address: upstream.Addr().String(), Framing: lineExchange("").Framing, TimeoutMilliseconds: 100, MaxFrames: 4, MaxTotalBytes: 1024, Mutations: []Mutation{m}})
			done <- r
		}()
		_, err := Run(context.Background(), lineExchange(front.Addr().String(), Step{Send: []byte("original\n"), Receive: true}))
		obs := <-done
		<-serverDone
		if err == nil {
			t.Fatal("failed proxy matched")
		}
		found := false
		for _, o := range obs {
			if o.Direction == "client" && bytes.Equal(o.Original, []byte("original\n")) && o.Error != "" && len(o.Transmitted) == 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("lost original on failure: %+v", obs)
		}
	}
}
