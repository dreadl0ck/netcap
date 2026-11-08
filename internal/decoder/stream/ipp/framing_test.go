package ipp

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func TestHTTPFramedIPP(t *testing.T) {
	body := []byte{2, 0, 0, 0, 0, 0, 0, 3, 3}
	response := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	input := append([]byte("HTTP/1.1 100 Continue\r\n\r\n"), response...)
	input = append(input, response...)
	for split := 0; split <= len(input); split++ {
		r := &ippReader{conversation: &core.ConversationInfo{Data: core.DataFragments{
			&core.StreamData{RawData: input[:split], Dir: reassembly.TCPDirServerToClient},
			&core.StreamData{RawData: input[split:], Dir: reassembly.TCPDirServerToClient},
		}}}
		count := 0
		r.decodeHTTPMessages(func(record *types.IPP, _ *core.StreamData) {
			count++
			if record.RequestID != int32(binary.BigEndian.Uint32(body[4:8])) {
				t.Fatal(record)
			}
		})
		if count != 2 {
			t.Fatalf("split=%d count=%d", split, count)
		}
	}
}

func TestIPPProbeSkipsOnlyInformationalHeaders(t *testing.T) {
	final := "HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: 9\r\n\r\n"
	for _, tc := range []struct {
		name, input string
		want        bool
	}{
		{"continue", "HTTP/1.1 100 Continue\r\n\r\n" + final, true},
		{"early-hints", "HTTP/1.1 103 Early Hints\r\n\r\n" + final, true},
		{"body-spoof", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + final, false},
		{"upgrade", "HTTP/1.1 101 Switching Protocols\r\n\r\n" + final, false},
		{"over-limit", strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 8) + final, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decoder.CanDecode(nil, []byte(tc.input)); got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestIPPFramingRejectsLossAndOversizedMessages(t *testing.T) {
	body := []byte{2, 0, 0, 0, 0, 0, 0, 3, 3}
	header := "HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: 9\r\n\r\n"
	for _, tc := range []struct {
		name string
		data core.DataFragments
	}{
		{"gap", core.DataFragments{&core.StreamData{RawData: []byte(header)}, &core.StreamData{RawData: body, SkippedBytes: 1}}},
		{"local-loss", core.DataFragments{&core.StreamData{RawData: []byte(header)}, &core.StreamData{RawData: body, DiscardedBytes: 1}}},
		{"partial", core.DataFragments{&core.StreamData{RawData: append([]byte(header), body[:4]...)}}},
		{"large-body", core.DataFragments{&core.StreamData{RawData: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: 99999999\r\n\r\n")}}},
		{"large-header", core.DataFragments{&core.StreamData{RawData: []byte("HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 16384) + "\r\n\r\n")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &ippReader{conversation: &core.ConversationInfo{Data: tc.data}}
			r.decodeHTTPMessages(func(*types.IPP, *core.StreamData) { t.Fatal("unqualified message emitted") })
		})
	}
}
