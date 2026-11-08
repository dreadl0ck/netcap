package sipaudit

import (
	"fmt"
	"strings"
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

func TestNegotiatedTelephoneEvents(t *testing.T) {
	for _, tc := range []struct {
		offer, answer string
		want          bool
	}{
		{"0-5", "5-15", true},
		{"0-4", "5-15", false},
		{"0-15,garbage", "0-15", false},
		{"0-15", "0-15,garbage", false},
		{"0-15,9-2", "0-15", false},
	} {
		t.Run(tc.offer+"/"+tc.answer, func(t *testing.T) {
			a := NewAssociations()
			for _, answer := range []bool{false, true} {
				s := signal("call", 1, answer, 1, 110)
				events := tc.offer
				if answer {
					events = tc.answer
				}
				s.Body = []byte(strings.ReplaceAll(string(s.Body), "fmtp:110 0-15", "fmtp:110 "+events))
				a.Observe(s)
			}
			for _, reverse := range []bool{false, true} {
				src, dst, sp, dp := "192.0.2.1", "192.0.2.2", int32(4000), int32(5000)
				if reverse {
					src, dst, sp, dp = dst, src, dp, sp
				}
				_, codec, ok := a.Lookup("", src, dst, sp, dp, 110, 2)
				if ok != tc.want || ok && (!codec.AllowsEvent(5) || codec.AllowsEvent(4) || codec.AllowsEvent(6)) {
					t.Fatalf("association=%v codec=%+v", ok, codec)
				}
			}
		})
	}
}

func TestSameCallIDDifferentDialogsAreAmbiguous(t *testing.T) {
	a := NewAssociations()
	for _, tag := range []string{"one", "two"} {
		for _, answer := range []bool{false, true} {
			s := signal("same-call", 1, answer, 1, 110)
			s.From = strings.ReplaceAll(s.From, "tag=one", "tag="+tag)
			a.Observe(s)
		}
	}
	if _, _, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 110, 2); ok {
		t.Fatal("overlapping dialogs with the same Call-ID were guessed")
	}
}

func TestMultipleTelephoneEventPayloadMaps(t *testing.T) {
	a := NewAssociations()
	offer := signal("call", 1, false, 1, 110)
	offer.Body = []byte(strings.ReplaceAll(string(offer.Body), "RTP/AVP 110", "RTP/AVP 110 111"))
	offer.Body = []byte(strings.ReplaceAll(string(offer.Body), "fmtp:110 0-15", "fmtp:110 0-5") + "a=rtpmap:111 telephone-event/8000\r\na=fmtp:111 6\r\n")
	answer := signal("call", 2, true, 1, 112)
	answer.Body = []byte(strings.ReplaceAll(string(answer.Body), "fmtp:112 0-15", "fmtp:112 5-15"))
	a.Observe(offer)
	a.Observe(answer)
	for range 100 {
		_, codec, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 112, 3)
		if !ok || codec.Events != "5,6" {
			t.Fatalf("nondeterministic peer payload map: %+v, %v", codec, ok)
		}
	}
}

func TestAssociationLifetimeAndNegotiation(t *testing.T) {
	a := NewAssociations()
	lookup := func(at int64, pt uint32) bool {
		_, _, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, pt, at)
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
			for i := range 300 {
				id := fmt.Sprintf("%d/%d", worker, i)
				a.Observe(signal(id, int64(i), false, 1, 110))
				a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 110, int64(i))
			}
		}()
	}
	wg.Wait()
	if len(a.calls) != 1200 || a.Coverage().Status != "complete" {
		t.Fatal("historical calls lost")
	}
	for i := range 40 {
		a.Observe(signal("bounded", int64(10000+i), false, int32(i), 110))
	}
	if len(a.calls["\x00bounded"].descriptions) != 40 {
		t.Fatal("historical descriptions lost")
	}
	for i := range 100 {
		a.Observe(signal("bounded", int64(20000+i), false, 39, 110))
	}
	if len(a.calls["\x00bounded"].descriptions) != 40 {
		t.Fatal("retransmissions consume slots")
	}
}

func TestAssociationBudgetPreservesHistoricalPrefix(t *testing.T) {
	a := NewAssociationsWithBudget(4096)
	a.Observe(signal("retained", 1, false, 1, 110))
	a.Observe(signal("retained", 2, true, 1, 110))
	for i := range 20 {
		a.Observe(signal(fmt.Sprint(i), int64(10+i), false, 1, 110))
	}
	c := a.Coverage()
	if c.Status != "capacity-loss" || c.RetainedBytes > c.LimitBytes || c.RejectedDescriptions == 0 || c.UntrustedFrom != 10 {
		t.Fatalf("coverage: %+v", c)
	}
	if id, _, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 110, 3); !ok || id != "retained" {
		t.Fatal("overflow erased retained historical attribution")
	}
	if _, _, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 110, 10); ok || a.Qualification(10) != CapacityLoss {
		t.Fatal("incomplete history trusted after overflow")
	}
	// TCP signaling can arrive after UDP observation with earlier capture time.
	a.Observe(signal("late-worker", 5, false, 1, 110))
	if a.Qualification(5) == "" || a.Qualification(4) != "" {
		t.Fatal("capture-time loss boundary")
	}
	a.Reset()
	if c := a.Coverage(); c.Status != "complete" || c.RetainedBytes != 0 || c.RejectedDescriptions != 0 {
		t.Fatalf("reset: %+v", c)
	}
}

func TestReverseBYEForksAndPortReuse(t *testing.T) {
	a := NewAssociations()
	a.Observe(signal("old", 1, false, 1, 110))
	for _, tag := range []string{"callee-a", "callee-b"} {
		s := signal("old", 2, true, 1, 110)
		s.To = "<sip:b@example.test>;tag=" + tag
		a.Observe(s)
	}
	lookup := func(at int64, want string) {
		t.Helper()
		id, _, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 110, at)
		if ok != (want != "") || id != want {
			t.Fatalf("at %d: id=%q ok=%v want=%q", at, id, ok, want)
		}
	}
	lookup(3, "") // identical media on two forks remains ambiguous
	a.Observe(&types.SIP{Timestamp: 3, CallID: "old", From: "<sip:a@example.test>;tag=one", MethodName: "BYE"})
	lookup(3, "") // a BYE missing the remote tag cannot terminate both forks
	bye := &types.SIP{Timestamp: 4, CallID: "old", From: "<sip:b@example.test>;tag=callee-a", To: "<sip:a@example.test>;tag=one", MethodName: "BYE", CSeqMethod: "BYE"}
	a.Observe(bye)
	lookup(4, "old") // the other fork survives
	bye2 := *bye
	bye2.Timestamp, bye2.From = 5, "<sip:b@example.test>;tag=callee-b"
	a.Observe(&bye2)
	lookup(5, "")
	a.Observe(signal("new", 6, false, 1, 110))
	a.Observe(signal("new", 7, true, 1, 110))
	lookup(8, "new")
	lookup(4, "old") // delayed RTP still belongs to the surviving old fork
}

func TestStopBeforeAnswerCannotReviveOffer(t *testing.T) {
	a := NewAssociations()
	a.Observe(signal("call", 1, false, 1, 110))
	a.Observe(&types.SIP{Timestamp: 2, CallID: "call", From: "<sip:a@example.test>;tag=one", MethodName: "CANCEL"})
	a.Observe(signal("call", 3, true, 1, 110))
	if _, _, ok := a.Lookup("", "192.0.2.1", "192.0.2.2", 4000, 5000, 110, 4); ok {
		t.Fatal("answer revived cancelled offer")
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

func TestAssociationScopeIsolation(t *testing.T) {
	for _, peer := range []string{"if:2", "if:1/vxlan:192.0.2.10,192.0.2.20:4789:false:0:8:0"} {
		t.Run(peer, func(t *testing.T) {
			a := NewAssociations()
			base := "if:1/vxlan:192.0.2.10,192.0.2.20:4789:false:0:7:0"
			observe := func(scope string, at int64, answer bool, pt int) {
				s := signal("same-call", at, answer, 1, pt)
				s.NetworkScope = scope
				a.Observe(s)
			}
			lookup := func(scope string, pt uint32) bool {
				id, codec, ok := a.Lookup(scope, "192.0.2.1", "192.0.2.2", 4000, 5000, pt, 10)
				if ok && (id != "same-call" || codec.Encoding != "telephone-event") {
					t.Fatalf("wrong association: %q %+v", id, codec)
				}
				return ok
			}
			observe(base, 1, false, 110)
			observe(peer, 2, true, 110)
			if lookup(base, 110) || lookup(peer, 110) {
				t.Fatal("offer and answer joined across scopes")
			}
			observe(base, 2, true, 110)
			if !lookup(base, 110) || lookup(peer, 110) || lookup("", 110) {
				t.Fatal("media inherited another scope's signaling")
			}
			observe(peer, 3, false, 111)
			observe(peer, 4, true, 111)
			if !lookup(base, 110) || lookup(base, 111) || !lookup(peer, 111) || lookup(peer, 110) {
				t.Fatal("same Call-ID/tag negotiations contaminated each other")
			}
			a.Observe(&types.SIP{NetworkScope: peer, Timestamp: 5, CallID: "same-call", From: "<sip:a@example.test>;tag=one", MethodName: "BYE"})
			if !lookup(base, 110) || lookup(peer, 111) {
				t.Fatal("BYE crossed scope boundary")
			}
		})
	}
}
