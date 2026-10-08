package protocoltest

import (
	"bytes"
	"context"
	"net"
	"testing"
)

func TestCampaignUDPControlsReproductionAndMinimization(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 129)
		for {
			n, peer, e := conn.ReadFrom(b)
			if e != nil {
				return
			}
			response := []byte("VALID")
			if bytes.Contains(b[:n], []byte{0xbe}) {
				response = []byte("REJECTED")
			}
			_, _ = conn.WriteTo(response, peer)
		}
	}()
	e := Exchange{Version: 1, Network: "udp", Address: conn.LocalAddr().String(), Framing: Framing{MaxBytes: 128}, MaxTotalBytes: 512, TimeoutMilliseconds: 500, Steps: []Step{{Send: []byte("AA"), Receive: true, Expect: []byte("VALID")}}}
	spec := Campaign{Metadata: fixtureMetadata(), Control: e, FailureMarker: []byte("REJECTED"), MaxCases: 16, MaxAttempts: 32}
	r, err := RunCampaign(context.Background(), spec)
	if err != nil || r.Before.Status != "matched" || r.After.Status != "matched" || r.Minimized == nil || !r.Minimized.Complete || !bytes.Equal(r.Minimized.Input, []byte{0xbe}) {
		t.Fatalf("campaign %+v %v", r, err)
	}
	for _, trial := range r.Trials {
		if len(trial.Result.Observations) != 2 || !bytes.Equal(trial.Input, trial.Result.Observations[0].Bytes) {
			t.Fatalf("missing reproduction evidence %+v", trial)
		}
	}
	spec.FailureMarker = []byte("VALID")
	if _, err = RunCampaign(context.Background(), spec); err == nil {
		t.Fatal("ambiguous oracle accepted")
	}
	spec.FailureMarker = []byte("REJECTED")
	spec.MaxAttempts = 1
	r, err = RunCampaign(context.Background(), spec)
	if err == nil || r.Minimized == nil || r.Minimized.Complete || r.After.Status != "matched" {
		t.Fatal("minimization budget/postcontrol", r, err)
	}
	_ = conn.Close()
	<-done
}

func TestAccessStateTransitionsAndResponseSelector(t *testing.T) {
	l := loopback(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 {
			c, e := l.Accept()
			if e != nil {
				return
			}
			f := lineExchange("").Framing
			// Greeting intentionally contains the marker; only the selected resource response counts.
			_, _ = c.Write([]byte("OWNER-MARKER greeting\n"))
			request, e := f.Read(c)
			if e == nil && string(request) == "LOGIN alice\n" {
				_, _ = c.Write([]byte("OK\n"))
				request, e = f.Read(c)
				loggedIn := true
				if string(request) == "LOGOUT\n" {
					loggedIn = false
					_, _ = c.Write([]byte("OK\n"))
					request, e = f.Read(c)
				}
				if e == nil && string(request) == "READ fixture\n" {
					response := "DENIED\n"
					if loggedIn {
						response = "OWNER-MARKER\n"
					}
					_, _ = c.Write([]byte(response))
				}
			}
			_ = c.Close()
		}
	}()
	cases := []AccessCase{}
	for _, logout := range []bool{false, true} {
		steps := []Step{{Receive: true, Contains: []byte("greeting")}, {Send: []byte("LOGIN alice\n"), Receive: true, Expect: []byte("OK\n")}}
		state := "authenticated"
		if logout {
			steps = append(steps, Step{Send: []byte("LOGOUT\n"), Receive: true, Expect: []byte("OK\n")})
			state = "logged-out"
		}
		steps = append(steps, Step{Send: []byte("READ fixture\n"), Receive: true})
		cases = append(cases, AccessCase{Metadata: fixtureMetadata(), Role: "alice", State: state, Resource: "fixture", Message: "READ", Allowed: !logout, Marker: []byte("OWNER-MARKER"), ResponseStep: len(steps) - 1, Exchange: lineExchange(l.Addr().String(), steps...)})
	}
	r, err := RunAccess(context.Background(), cases)
	<-done
	if err != nil || len(r) != 2 || r[0].Status != "matched" || r[1].Status != "matched" || r[1].MarkerReturned {
		t.Fatalf("state/response scope %+v %v", r, err)
	}
}
