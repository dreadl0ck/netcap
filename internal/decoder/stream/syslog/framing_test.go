package syslog

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func logFragment(raw []byte, server bool, ns int64) *core.StreamData {
	d := &core.StreamData{RawData: raw, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, ns)}}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}
	return d
}
func readLogs(transport core.TransportProtocol, data core.DataFragments) []*types.Syslog {
	s := &syslogReader{conversation: &core.ConversationInfo{Transport: transport, Data: data, ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 514, CommunityID: "known"}}
	var got []*types.Syslog
	s.decodeMessages(func(m *types.Syslog) { got = append(got, m) })
	return got
}

func TestTCPFramingSplitDirections(t *testing.T) {
	msg := "<165>1 2003-10-11T22:14:15.003Z host app - ID47 - payload"
	for _, wire := range []string{fmt.Sprintf("%d %s", len(msg), msg), msg + "\r\n"} {
		for split := 1; split < len(wire); split++ {
			got := readLogs(core.TCP, core.DataFragments{logFragment([]byte(wire[:split]), false, 11), logFragment([]byte(wire), true, 12), logFragment([]byte(wire[split:]+wire), false, 13)})
			if len(got) != 3 {
				t.Fatalf("split %d: %d messages", split, len(got))
			}
			if got[0].SrcIP != "192.0.2.2" || got[0].SrcPort != 514 || got[0].Timestamp != 12 || got[1].Timestamp != 11 || got[1].Protocol != "TCP" || got[1].Message != "payload" || got[2].Timestamp != 13 || got[2].CommunityID != "known" {
				t.Fatalf("split %d: %+v", split, got)
			}
		}
	}
}

func TestSyslogBoundsGapsAndDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport core.TransportProtocol
		data      core.DataFragments
		count     int
	}{
		{"udp", core.UDP, core.DataFragments{logFragment([]byte("<13>payload"), false, 1)}, 1},
		{"no-udp-join", core.UDP, core.DataFragments{logFragment([]byte("<1"), false, 1), logFragment([]byte("3>payload"), false, 2)}, 0},
		{"invalid-pri", core.UDP, core.DataFragments{logFragment([]byte("<999>payload"), false, 1)}, 0},
		{"truncated-octets", core.TCP, core.DataFragments{logFragment([]byte("100 <13>payload"), false, 1)}, 0},
		{"oversized", core.TCP, core.DataFragments{logFragment([]byte("9999999 <13>payload\n"), false, 1)}, 0},
		{"zero", core.TCP, core.DataFragments{logFragment([]byte("0 <13>payload\n"), false, 1)}, 0},
		{"non-digits", core.TCP, core.DataFragments{logFragment([]byte("1x <13>payload\n"), false, 1)}, 0},
		{"bounded-line", core.TCP, core.DataFragments{logFragment(append([]byte("<13>"), bytes.Repeat([]byte{'x'}, maxSyslogMessage+10)...), false, 1)}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readLogs(tc.transport, tc.data); len(got) != tc.count {
				t.Fatalf("got %d want %d", len(got), tc.count)
			}
		})
	}
	for _, local := range []bool{false, true} {
		d := logFragment([]byte("<13>after\n"), false, 2)
		if local {
			d.DiscardedBytes = 1
		} else {
			d.SkippedBytes = 1
		}
		got := readLogs(core.TCP, core.DataFragments{logFragment([]byte("<13>before"), false, 1), d})
		if len(got) != 1 || got[0].Message != "after" || got[0].Timestamp != 2 {
			t.Fatalf("gap joined: %+v", got)
		}
	}
}

func TestSyslogSelection(t *testing.T) {
	if Decoder.Typ != core.All {
		t.Fatal("TCP unreachable")
	}
	for _, tc := range []struct {
		wire string
		want bool
	}{{"<13>message", true}, {"12 <13>message", true}, {"<999>message", false}, {"<>message", false}, {"1x <13>message", false}, {"0 <13>message", false}} {
		if got := Decoder.CanDecode([]byte(tc.wire), nil); got != tc.want {
			t.Fatalf("%q got %v", tc.wire, got)
		}
	}
}
