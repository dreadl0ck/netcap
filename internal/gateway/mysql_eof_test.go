package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func mysqlEOFConversation(t *testing.T, deprecate, binaryRows bool, limit int, end []byte) (bool, error, []byte) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	packets := [][]byte{{1}, mysqlFixtureColumn()}
	if !deprecate {
		packets = append(packets, mysqlEOF(2))
	}
	row := []byte{1, 'x'}
	if binaryRows {
		row = []byte{0, 0, 7, 0, 0, 0}
	}
	packets = append(packets, row, end)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		for i, packet := range packets {
			if _, err := server.Write(mysqlPacket(byte(i+1), packet)); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	g := &Gateway{cfg: Config{MaxMessageBytes: limit, MaxStateEntries: 16, MaxSessionMessages: 16, IOTimeout: time.Second}}
	conversation := mysqlConversation{g: g, ctx: ctx, c: client, seq: 1}
	ok, err := conversation.result(deprecate, binaryRows)
	client.Close()
	<-done
	if ok && conversation.packets != len(packets) {
		t.Fatalf("premature terminator: read %d of %d packets", conversation.packets, len(packets))
	}
	return ok, err, conversation.wire
}

func TestMySQLResultDeprecatedEOFInfo(t *testing.T) {
	for _, binaryRows := range []bool{false, true} {
		for _, info := range [][]byte{nil, []byte("x"), []byte("ok"), []byte("Rows matched: 1"), bytes.Repeat([]byte{'x'}, 512), {0, 0xfc, 0xfe, 0xff}} {
			t.Run(fmt.Sprintf("binary=%t/info=%d", binaryRows, len(info)), func(t *testing.T) {
				end := append([]byte{0xfe, 0, 0, 2, 0, 0, 0}, info...)
				ok, err, wire := mysqlEOFConversation(t, true, binaryRows, 4096, end)
				if !ok || err != nil || !bytes.HasSuffix(wire, mysqlPacket(4, end)) {
					t.Fatalf("OK-as-EOF with %d info bytes rejected/changed: success=%t err=%v", len(info), ok, err)
				}
			})
		}
	}
}

func TestMySQLResultMalformedEOFPackets(t *testing.T) {
	for name, end := range map[string][]byte{
		"missing-affected-rows":         {0xfe},
		"truncated-affected-fc":         {0xfe, 0xfc, 1},
		"truncated-affected-fd":         {0xfe, 0xfd, 1, 0},
		"truncated-affected-fe":         {0xfe, 0xfe, 0, 0, 0, 0, 0, 0, 0},
		"invalid-affected-null":         {0xfe, 0xfb, 0, 2, 0, 0, 0},
		"truncated-insert-id":           {0xfe, 0, 0xfc, 1},
		"invalid-insert-id":             {0xfe, 0, 0xff, 2, 0, 0, 0},
		"truncated-status":              {0xfe, 0, 0, 2},
		"truncated-warnings":            {0xfe, 0, 0, 2, 0, 0},
		"legacy-eof-in-deprecated-mode": mysqlEOF(2),
	} {
		t.Run(name, func(t *testing.T) {
			ok, err, _ := mysqlEOFConversation(t, true, false, 4096, end)
			if ok || !errors.Is(err, errFrame) {
				t.Fatalf("malformed OK-as-EOF accepted: success=%t err=%v", ok, err)
			}
		})
	}
	for _, deprecate := range []bool{false, true} {
		for _, status := range []uint16{2, 2 | 8, 2 | 0x40} {
			t.Run(fmt.Sprintf("deprecate=%t/status=%x", deprecate, status), func(t *testing.T) {
				end := mysqlEOF(status)
				if deprecate {
					end = mysqlOK(status)
					end[0] = 0xfe
					end = append(end, []byte("Rows matched: 1")...)
				}
				ok, err, _ := mysqlEOFConversation(t, deprecate, false, 4096, end)
				if status == 2 {
					if !ok || err != nil {
						t.Fatalf("valid terminator rejected: %v", err)
					}
				} else if ok || !errors.Is(err, errFrame) {
					t.Fatalf("unsupported result/cursor status accepted: success=%t err=%v", ok, err)
				}
			})
		}
	}
}

func TestMySQLResultEOFInfoResourceBounds(t *testing.T) {
	for _, size := range []int{400, 480, 600} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			end := append([]byte{0xfe, 0, 0, 2, 0, 0, 0}, bytes.Repeat([]byte{'x'}, size)...)
			ok, err, _ := mysqlEOFConversation(t, true, false, 512, end)
			if size == 400 {
				if !ok || err != nil {
					t.Fatalf("bounded info rejected: %v", err)
				}
			} else if ok || !errors.Is(err, errFrame) {
				t.Fatalf("packet/conversation limit bypass: success=%t err=%v", ok, err)
			}
		})
	}
}

func TestMySQLResultTruncatedEOFPacket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		for i, packet := range [][]byte{{1}, mysqlFixtureColumn(), {1, 'x'}} {
			if _, err := server.Write(mysqlPacket(byte(i+1), packet)); err != nil {
				return
			}
		}
		end := mysqlPacket(4, []byte{0xfe, 0, 0, 2, 0, 0, 0})
		end[0] = 22
		server.Write(end)
	}()
	g := &Gateway{cfg: Config{MaxMessageBytes: 4096, MaxStateEntries: 16, MaxSessionMessages: 16, IOTimeout: time.Second}}
	conversation := mysqlConversation{g: g, ctx: t.Context(), c: client, seq: 1}
	ok, err := conversation.result(true, false)
	client.Close()
	<-done
	if ok || !errors.Is(err, errFrame) {
		t.Fatalf("truncated packet accepted: success=%t err=%v", ok, err)
	}
}

func TestMySQLResultFEPrefixDiscrimination(t *testing.T) {
	for _, size := range []int{7, 8, 9, 22, 0xffffff - 1, 0xffffff} {
		packet := make([]byte, size)
		packet[0] = 0xfe
		if got := mysqlResultEOF(packet, false); got != (size < 9) {
			t.Fatalf("legacy discriminator at %d: %t", size, got)
		}
		if got := mysqlResultEOF(packet, true); got != (size < 0xffffff) {
			t.Fatalf("deprecated discriminator at %d: %t", size, got)
		}
	}
	// A canonical 0xfe text length requires >= 2^24 value bytes, irrespective
	// of their contents. It is a row, but needs unsupported continuation framing.
	row := make([]byte, (1<<24)+9)
	row[0] = 0xfe
	binary.LittleEndian.PutUint64(row[1:9], 1<<24)
	if !mysqlTextRow(row, 1) || mysqlResultEOF(row, true) || mysqlResultEOF(row, false) {
		t.Fatal("canonical 0xfe text row mistaken for a terminator")
	}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		server.Write([]byte{0xff, 0xff, 0xff, 0})
	}()
	g := &Gateway{cfg: Config{MaxMessageBytes: 16 << 20, IOTimeout: time.Second}}
	packet, err := g.mysqlRead(t.Context(), client, 0, false)
	<-done
	if len(packet) != 0 || !errors.Is(err, errFrame) {
		t.Fatal("continuation packet accepted as a bounded row/terminator")
	}
}
