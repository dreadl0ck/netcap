package sip

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func fragment(text string, at int64, gap int) *core.StreamData {
	return &core.StreamData{RawData: []byte(text), SkippedBytes: gap, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, at)}}
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
