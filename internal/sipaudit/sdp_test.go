package sipaudit

import (
	"fmt"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func signal(id string, at int64, answer bool, seq int32, pt int) *types.SIP {
	ip, port := "192.0.2.1", 4000
	if answer {
		ip, port = "192.0.2.2", 5000
	}
	return &types.SIP{Timestamp: at, CallID: id, From: "<sip:a@example.test>;tag=one", CSeqNumber: seq, CSeqMethod: "INVITE", MethodName: "INVITE", IsResponse: answer, ResponseCode: 200,
		ContentType: "application/sdp", Body: []byte(fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP %d\r\na=rtpmap:%d telephone-event/8000\r\na=fmtp:%d 0-15\r\n", ip, port, pt, pt, pt))}
}

func TestAssociationLifetimeAndNegotiation(t *testing.T) {
	a := NewAssociations()
	lookup := func(at int64, pt uint32) bool {
		_, _, ok := a.Lookup("192.0.2.1", "192.0.2.2", 4000, 5000, pt, at)
		return ok
	}
	a.Observe(signal("call", 1, true, 1, 110)) // answer delivered before offer by another worker
	if lookup(2, 110) {
		t.Fatal("answer alone established association")
	}
	a.Observe(signal("call", 0, false, 1, 110))
	if lookup(0, 110) || !lookup(1, 110) || lookup(2, 101) || lookup(associationLifetime+1, 110) {
		t.Fatal("time/PT qualification")
	}
	a.Observe(signal("call", 3, false, 2, 111))
	a.Observe(signal("call", 4, true, 2, 111))
	if lookup(4, 110) || !lookup(4, 111) || !lookup(2, 110) {
		t.Fatal("renegotiation lost temporal mapping")
	}
	a.Observe(&types.SIP{Timestamp: 5, CallID: "call", From: "<sip:a@example.test>;tag=one", MethodName: "BYE"})
	if lookup(5, 111) || !lookup(4, 111) {
		t.Fatal("BYE/history")
	}
	a.Reset()
	if lookup(2, 110) {
		t.Fatal("cross-capture state")
	}
	a.Observe(signal("call", 0, false, 1, 110))
	a.Observe(signal("call", 1, true, 1, 110))
	a.Observe(signal("other", 0, false, 1, 110))
	a.Observe(signal("other", 1, true, 1, 110))
	if lookup(2, 110) {
		t.Fatal("ambiguous overlapping calls guessed")
	}
}

func TestAssociationBoundsAndConcurrentAccess(t *testing.T) {
	a := NewAssociations()
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range maxCalls {
				id := fmt.Sprintf("%d/%d", worker, i)
				a.Observe(signal(id, int64(i), false, 1, 110))
				a.Lookup("192.0.2.1", "192.0.2.2", 4000, 5000, 110, int64(i))
			}
		}()
	}
	wg.Wait()
	if len(a.calls) > maxCalls {
		t.Fatal("call bound")
	}
	for i := range 40 {
		a.Observe(signal("bounded", int64(10000+i), false, int32(i), 110))
	}
	if len(a.calls["bounded\x00one"].descriptions) != maxDescriptions {
		t.Fatal("description bound")
	}
	for i := range 100 {
		a.Observe(signal("bounded", int64(20000+i), false, 39, 110))
	}
	if len(a.calls["bounded\x00one"].descriptions) != maxDescriptions {
		t.Fatal("retransmissions consume slots")
	}
}

func TestSDPRejectsUnusableMedia(t *testing.T) {
	for _, body := range []string{
		"v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/AVP 0\r\n",
		"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n",
		"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/SAVP 0\r\n",
		"v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 110\r\n",
	} {
		m := parseSDP([]byte(body))
		if len(m) != 1 || (!m[0].disabled && len(m[0].codecs) > 0) {
			t.Fatalf("usable malformed media: %+v", m)
		}
	}
}
