package protocoltest

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestMutationLengthRepairAndLimits(t *testing.T) {
	f := Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 64}
	got, err := MutateFrame([]byte{0, 1, 'a'}, f, Mutation{Offset: 3, Insert: []byte("bc"), RepairLength: true})
	if err != nil || !bytes.Equal(got, []byte{0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("repair: %x %v", got, err)
	}
	for _, m := range []Mutation{{Offset: -1}, {Offset: 4}, {Offset: 1, Delete: 3}, {Insert: make([]byte, 65)}, {Offset: 0, Delete: 3, RepairLength: true}} {
		if _, err := MutateFrame([]byte{0, 1, 'a'}, f, m); err == nil {
			t.Fatal("invalid mutation accepted")
		}
	}
}

func TestProxyBidirectionalMutationAndHalfClose(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	framing := Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 64}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		data, err := framing.Read(conn)
		if err == nil {
			_, err = conn.Write(data)
		}
		serverDone <- err
	}()
	type completion struct {
		records []ProxyObservation
		err     error
	}
	done := make(chan completion, 1)
	go func() {
		records, err := ProxyOne(context.Background(), listener, Proxy{Address: upstream.Addr().String(), Framing: framing, TimeoutMilliseconds: 3000, MaxFrames: 4, MaxTotalBytes: 256, Mutations: []Mutation{{Direction: "client", Frame: 0, Offset: 3, Insert: []byte("bc"), RepairLength: true}}})
		done <- completion{records, err}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte{0, 1, 'a'}); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := framing.Read(client)
	if err != nil || !bytes.Equal(got, []byte{0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("proxy response: %x %v", got, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.records) != 2 {
		t.Fatalf("trace count: %d", len(result.records))
	}
	for _, record := range result.records {
		if record.Direction == "client" && (!bytes.Equal(record.Original, []byte{0, 1, 'a'}) || !bytes.Equal(record.Transmitted, got)) {
			t.Fatalf("before/after trace: %+v", record)
		}
	}
}
