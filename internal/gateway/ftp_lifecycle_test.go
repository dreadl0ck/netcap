package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type ftpObservedListener struct {
	*net.TCPListener
	closed chan struct{}
	once   sync.Once
}

func (l *ftpObservedListener) Close() error {
	err := l.TCPListener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func ftpTestListener(t *testing.T) *ftpObservedListener {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	observed := &ftpObservedListener{TCPListener: l, closed: make(chan struct{})}
	t.Cleanup(func() { observed.Close() })
	return observed
}

func ftpWantRefused(t *testing.T, address string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		c.Close()
		t.Error("passive listener accepted another connection")
	} else if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("wanted connection refused, got %v", err)
	}
}

func TestFTPDataListenerSingleUseWhileUploadBuffered(t *testing.T) {
	l := ftpTestListener(t)
	g, err := New(Config{Protocol: "ftp", Upstream: l.Addr().String(), MaxMessageBytes: 512, IOTimeout: time.Second}, compileGatewayPolicy(t, `Body contains "forbidden"`))
	if err != nil {
		t.Fatal(err)
	}
	control, client := net.Pipe()
	up, origin := net.Pipe()
	defer control.Close()
	defer client.Close()
	defer up.Close()
	defer origin.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	originBytes := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(origin); originBytes <- b }()
	done := make(chan bool, 1)
	go func() {
		done <- g.ftpTransfer(t.Context(), control, up, nil, l, l.Addr().String(), "127.0.0.1", "STOR", []byte("STOR blocked.txt\r\n"), map[string]string{"ftp.path": "blocked.txt"})
	}()
	r := bufio.NewReader(client)
	if b, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(b, "150 ") {
		t.Fatalf("preliminary reply %q %v", b, err)
	}
	d, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	select {
	case <-l.closed:
	case <-time.After(time.Second):
		t.Fatal("accepted data listener remained open while STOR was buffering")
	}
	select {
	case <-done:
		t.Fatal("upload completed before receiving its body")
	default:
	}
	ftpWantRefused(t, l.Addr().String())
	if _, err := d.Write([]byte("forbidden")); err != nil {
		t.Fatal(err)
	}
	d.CloseWrite()
	if b, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(b, "550 ") {
		t.Fatalf("content denial %q %v", b, err)
	}
	if !<-done {
		t.Fatal("denied transfer did not finish its control reply")
	}
	up.Close()
	if b := <-originBytes; len(b) != 0 {
		t.Fatalf("denied STOR reached origin: %q", b)
	}
}

type ftpCloseCheckConn struct {
	net.Conn
	check func()
}

func (c ftpCloseCheckConn) Close() error {
	c.check()
	return c.Conn.Close()
}

func TestFTPPassiveClosureBeforeUpstreamAndLateRegistration(t *testing.T) {
	for _, mode := range []string{"cancel-before-registration", "close-before-registration", "registered-before-cancel"} {
		t.Run(mode, func(t *testing.T) {
			l := ftpTestListener(t)
			up, origin := net.Pipe()
			defer origin.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := &ftpSession{up: ftpCloseCheckConn{Conn: up, check: func() {
				if mode == "registered-before-cancel" {
					select {
					case <-l.closed:
					default:
						t.Error("upstream closed before passive listener")
					}
					ftpWantRefused(t, l.Addr().String())
				}
			}}}
			defer s.close()
			if mode == "registered-before-cancel" && !s.registerPassive(ctx, l) {
				t.Fatal("live session rejected listener")
			}
			if mode == "close-before-registration" {
				s.close()
			} else {
				cancel()
			}
			if mode != "registered-before-cancel" && s.registerPassive(ctx, l) {
				t.Fatal("listener registered after cancellation or close")
			}
			closed := make(chan struct{})
			context.AfterFunc(ctx, func() { s.close(); close(closed) })
			cancel()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("session did not cancel")
			}
			ftpWantRefused(t, l.Addr().String())
		})
	}
}
