package flowexport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReceiveLoopbackUsesExportDecoderAndCancels(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r, err := NewRecorder(t.TempDir(), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Receive(ctx, conn, r) }()
	client, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, data := range [][]byte{nf9(0, set(0, shorts(256, 1, 8, 4))), nf9(1, set(256, words(0xc0000201)))} {
		if _, err := client.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.engine.Health().Records != 1 {
		if time.Now().After(deadline) {
			t.Fatal("loopback record never decoded")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle receiver did not stop")
	}
}
