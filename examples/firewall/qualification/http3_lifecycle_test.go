//go:build coraza && http3

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Reproduce the Darwin UDP demultiplexing fault with owned endpoints only.
// The old http3.Transport client used this dual-stack wildcard socket shape.
func TestHTTP3DualStackPortCollision(t *testing.T) {
	sink, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	port := sink.LocalAddr().(*net.UDPAddr).Port
	legacy, err := net.ListenPacket("udp", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		t.Logf("kernel prevents the overlapping wildcard bind: %v", err)
		return
	}
	defer legacy.Close()
	origin, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	for _, c := range []net.PacketConn{sink, legacy, origin} {
		c.SetDeadline(time.Now().Add(time.Second))
	}
	payload := []byte("owned-udp-collision-probe")
	if _, err := legacy.WriteTo(payload, origin.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	var b [128]byte
	n, client, err := origin.ReadFrom(b[:])
	if err != nil || !bytes.Equal(b[:n], payload) {
		t.Fatalf("origin probe: %q %v", b[:n], err)
	}
	if _, err := origin.WriteTo(b[:n], client); err != nil {
		t.Fatal(err)
	}
	n, _, err = sink.ReadFrom(b[:])
	if err != nil || !bytes.Equal(b[:n], payload) {
		t.Fatalf("overlapping IPv4 sink did not intercept reply: %q %v", b[:n], err)
	}
	t.Logf("reply to dual-stack %s diverted to owned IPv4 %s", legacy.LocalAddr(), sink.LocalAddr())
}

func TestHTTP3FixtureOwnsClientSocket(t *testing.T) {
	p, err := newProfile(context.Background(), 0, false, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	transport := p.Client.Transport.(*http3.Transport)
	if transport.Dial == nil {
		t.Fatal("fixture uses an unowned dual-stack client socket")
	}
	status, actual, err := p.request(training[0])
	if err != nil || status != 200 || actual != 3 {
		t.Fatalf("owned HTTP3 socket: status=%d protocol=%d err=%v", status, actual, err)
	}
}
