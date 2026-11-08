package sip

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func fragment(text string, at int64, gap int) *core.StreamData {
	return &core.StreamData{RawData: []byte(text), SkippedBytes: gap, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, at)}}
}

func TestTransportBoundariesDoNotAuthorizeMedia(t *testing.T) {
	body := "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n"
	one := "INVITE sip:b@example.test SIP/2.0\r\nFrom: <sip:a@example.test>;tag=a\r\nTo: <sip:b@example.test>\r\nCall-ID: boundary\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	for _, observation := range []string{"after-fin", "after-rst"} {
		for _, split := range []bool{false, true} {
			t.Run(observation+"/split="+strconv.FormatBool(split), func(t *testing.T) {
				old := sipaudit.Media
				sipaudit.Media = sipaudit.NewAssociations()
				t.Cleanup(func() { sipaudit.Media = old })
				before, post := fragment(one, 1, 0), fragment(strings.ReplaceAll(one, "Call-ID: boundary", "Call-ID: post-close"), 2, 0)
				if split {
					before.RawData, post.RawData = []byte(one[:20]), []byte(one[20:])
				}
				post.TCPObservation = observation
				r := reader{&core.ConversationInfo{ClientData: core.DataFragments{before, post}}}
				var records []*types.SIP
				r.decode(func(s *types.SIP) { records = append(records, s) })
				if split {
					if len(records) != 0 {
						t.Fatal("joined INVITE across transport boundary")
					}
				} else if len(records) != 2 || records[0].TCPObservation != "" || records[1].TCPObservation != observation {
					t.Fatalf("qualification: %+v", records)
				}
				want := 1
				if split {
					want = 0
				}
				if c := sipaudit.Media.Coverage(); c.RetainedDescriptions != want {
					t.Fatalf("unconfirmed signaling entered associations: %+v", c)
				}
			})
		}
	}
}

func TestDiscardedBytesBreakFraming(t *testing.T) {
	one := "OPTIONS sip:a@example.test SIP/2.0\r\nl: 0\r\n\r\n"
	for _, prefix := range []string{"", one[:10], one} {
		loss := fragment(one, 2, 0)
		loss.DiscardedBytes = 20
		r := reader{&core.ConversationInfo{ClientData: core.DataFragments{fragment(prefix, 1, 0), loss}}}
		var records []*types.SIP
		r.decode(func(s *types.SIP) { records = append(records, s) })
		want := 0
		if prefix == one {
			want = 1
		}
		if len(records) != want {
			t.Fatalf("discarded bytes joined: %d want %d", len(records), want)
		}
	}
}

func TestFramingAndCaptureLoss(t *testing.T) {
	one := "OPTIONS sip:a@example.test SIP/2.0\r\nl: 0\r\n\r\n"
	body := one
	message := "MESSAGE sip:a@example.test SIP/2.0\r\nl: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	for _, tc := range []struct {
		name      string
		fragments core.DataFragments
		count     int
		times     []int64
	}{
		{"split/coalesced/body", core.DataFragments{fragment(message[:5], 1, 0), fragment(message[5:]+one, 2, 0)}, 2, []int64{1, 2}},
		{"leading unknown", core.DataFragments{fragment(one, 1, -1)}, 1, []int64{1}},
		{"internal known gap", core.DataFragments{fragment(one[:10], 1, 0), fragment(one, 2, 4)}, 0, nil},
		{"internal unknown gap", core.DataFragments{fragment(one, 1, 0), fragment(one, 2, -1)}, 1, []int64{1}},
		{"malformed length no resync", core.DataFragments{fragment(strings.Replace(one, "l: 0", "l: -1", 1)+one, 1, 0)}, 0, nil},
		{"incomplete", core.DataFragments{fragment(one[:10], 1, 0)}, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var records []*types.SIP
			r := reader{&core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientData: tc.fragments}}
			r.decode(func(s *types.SIP) { records = append(records, s) })
			if len(records) != tc.count {
				t.Fatalf("count %d expected %d", len(records), tc.count)
			}
			for i, s := range records {
				if s.Timestamp != tc.times[i] {
					t.Fatalf("timestamp %d expected %d", s.Timestamp, tc.times[i])
				}
			}
		})
	}
}
