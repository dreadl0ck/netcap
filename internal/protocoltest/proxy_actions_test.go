package protocoltest

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxySuccessfulDropDuplicateDelayInjectionAndState(t *testing.T) {
	type targetResult struct {
		messages []string
		delay    time.Duration
		err      error
	}
	upstream := loopback(t)
	targetDone := make(chan targetResult, 1)
	go func() {
		r := targetResult{}
		defer func() { targetDone <- r }()
		c, e := upstream.Accept()
		if e != nil {
			r.err = e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		f := lineExchange("").Framing
		count := 0
		authenticated := false
		var authTime time.Time
		for {
			b, e := f.Read(c)
			if e == io.EOF {
				return
			}
			if e != nil {
				r.err = e
				return
			}
			r.messages = append(r.messages, string(b))
			reply := "DENIED\n"
			switch string(b) {
			case "AUTH\n":
				authenticated = true
				authTime = time.Now()
				reply = "READY\n"
			case "ADD\n":
				if authenticated {
					count++
					if count == 1 {
						r.delay = time.Since(authTime)
					}
					reply = fmt.Sprintf("ADDED %d\n", count)
				}
			case "GET\n":
				if authenticated {
					reply = fmt.Sprintf("COUNT %d\n", count)
				}
			}
			if _, e = c.Write([]byte(reply)); e != nil {
				r.err = e
				return
			}
		}
	}()
	front := loopback(t)
	type result struct {
		o   []ProxyObservation
		err error
	}
	done := make(chan result, 1)
	spec := Proxy{Address: upstream.Addr().String(), Framing: lineExchange("").Framing, TimeoutMilliseconds: 2500, MaxFrames: 16, MaxTotalBytes: 4096, Injections: []Injection{{Direction: "client", BeforeFrame: 0, Message: []byte("AUTH\n")}}, Mutations: []Mutation{{Direction: "client", Frame: 0, Drop: true}, {Direction: "client", Frame: 1, Copies: 2, DelayMilliseconds: 60}}}
	go func() { o, e := ProxyOne(context.Background(), front, spec); done <- result{o, e} }()
	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	f := spec.Framing
	// No client bytes have been sent: this reply proves standalone injection.
	if b, e := f.Read(c); e != nil || string(b) != "READY\n" {
		t.Fatalf("standalone injection %q %v", b, e)
	}
	if _, err = c.Write([]byte("NOOP\nADD\nGET\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	for _, want := range []string{"ADDED 1\n", "ADDED 2\n", "COUNT 2\n"} {
		b, e := f.Read(c)
		if e != nil || string(b) != want {
			t.Fatalf("state response %q want %q: %v", b, want, e)
		}
	}
	target := <-targetDone
	proxy := <-done
	if target.err != nil || proxy.err != nil || fmt.Sprint(target.messages) != fmt.Sprint([]string{"AUTH\n", "ADD\n", "ADD\n", "GET\n"}) || target.delay < 60*time.Millisecond {
		t.Fatalf("state/actions target=%+v proxyErr=%v", target, proxy.err)
	}
	injected, dropped, duplicated := false, false, false
	for _, o := range proxy.o {
		if o.Direction != "client" {
			continue
		}
		switch {
		case o.Injected:
			injected = len(o.Original) == 0 && bytes.Equal(o.Planned, []byte("AUTH\n")) && bytes.Equal(o.Transmitted, []byte("AUTH\n"))
		case o.Frame == 0:
			dropped = string(o.Original) == "NOOP\n" && len(o.Transmitted) == 0 && o.Copies == 0
		case o.Frame == 1:
			duplicated = string(o.Original) == "ADD\n" && string(o.Transmitted) == "ADD\nADD\n" && o.Copies == 2
		}
	}
	if !injected || !dropped || !duplicated {
		t.Fatalf("missing action evidence injected=%v dropped=%v duplicated=%v", injected, dropped, duplicated)
	}
	for _, message := range [][]byte{[]byte("missing-delimiter"), []byte("ONE\nTWO\n"), nil} {
		spec.Injections[0].Message = message
		if _, err := ProxyOne(context.Background(), front, spec); err == nil {
			t.Fatal("incomplete/multiple injected messages accepted")
		}
	}
}

type smallWriteListener struct{ net.Listener }

func (l smallWriteListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e == nil {
		e = c.(*net.TCPConn).SetWriteBuffer(1024)
		if e != nil {
			_ = c.Close()
		}
	}
	return c, e
}

func TestProxySlowReaderBackpressureCompletesAndStopsBoundedly(t *testing.T) {
	for _, drain := range []bool{true, false} {
		t.Run(fmt.Sprint(drain), func(t *testing.T) {
			framing := Framing{Kind: "length-prefix", LengthBytes: 4, ByteOrder: "big", MaxBytes: 600000}
			payload := bytes.Repeat([]byte("x"), 512<<10)
			wire := make([]byte, len(payload)+4)
			binary.BigEndian.PutUint32(wire, uint32(len(payload)))
			copy(wire[4:], payload)
			upstream := loopback(t)
			targetDone := make(chan struct{})
			go func() {
				defer close(targetDone)
				c, e := upstream.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = c.Write(wire)
			}()
			front := smallWriteListener{loopback(t)}
			timeout := 2500
			if !drain {
				timeout = 150
			}
			type result struct {
				o   []ProxyObservation
				err error
			}
			done := make(chan result, 1)
			go func() {
				o, e := ProxyOne(context.Background(), front, Proxy{Address: upstream.Addr().String(), Framing: framing, TimeoutMilliseconds: timeout, MaxFrames: 4, MaxTotalBytes: 2 << 20})
				done <- result{o, e}
			}()
			c, e := net.Dial("tcp", front.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			// Stay below the payload size without Linux's tiny-window persist delays.
			_ = c.(*net.TCPConn).SetReadBuffer(32 << 10)
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_ = c.(*net.TCPConn).CloseWrite()
			if drain {
				select {
				case r := <-done:
					t.Fatalf("proxy bypassed slow reader: err=%v observations=%d", r.err, len(r.o))
				case <-time.After(60 * time.Millisecond):
				}
				// Slow, bounded reads release backpressure rather than buffering whole frames elsewhere.
				got := make([]byte, 0, len(wire))
				chunk := make([]byte, 8192)
				for len(got) < len(wire) {
					n, err := c.Read(chunk)
					got = append(got, chunk[:n]...)
					if err != nil {
						t.Fatal(err)
					}
					time.Sleep(time.Millisecond)
				}
				if !bytes.Equal(got, wire) {
					t.Fatal("slow reader byte stream changed")
				}
			}
			var r result
			select {
			case r = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("proxy ignored deadline under backpressure")
			}
			<-targetDone
			found := false
			for _, o := range r.o {
				if o.Direction == "server" && len(o.Original) > 0 {
					found = true
					if !bytes.Equal(o.Original, wire) {
						t.Fatal("lost original under backpressure")
					}
					if drain && !bytes.Equal(o.Transmitted, wire) {
						t.Fatal("incomplete successful transmission")
					}
					if !drain && (len(o.Transmitted) >= len(wire) || o.Error == "") {
						t.Fatal("timeout falsely reported full transmission")
					}
				}
			}
			if !found || (drain && r.err != nil) || (!drain && r.err == nil) {
				t.Fatalf("backpressure result observations=%d err=%v", len(r.o), r.err)
			}
		})
	}
}
