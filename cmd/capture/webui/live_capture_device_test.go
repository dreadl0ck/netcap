//go:build !appstore

package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Opt in with the loopback device identifier and a matching net helper on PATH.
func TestOwnedLoopbackCapture(t *testing.T) {
	nic := os.Getenv("NETCAP_TEST_LOOPBACK")
	if nic == "" {
		t.Skip("requires loopback capture permissions and a net helper")
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	body, _ := json.Marshal(liveCaptureRequest{Interface: nic, BPF: fmt.Sprintf("udp dst port %d", port), DurationSeconds: 30, RetentionMB: 2})
	s := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	w := httptest.NewRecorder()
	s.handleOwnedLiveCapture(w, httptest.NewRequest("POST", "/api/live-capture", strings.NewReader(string(body))))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	id := s.ownedLive.SessionID
	for range 20 {
		_, err := listener.WriteTo([]byte("netcap loopback test"), listener.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	w = httptest.NewRecorder()
	s.handleStopCapture(w, httptest.NewRequest("POST", "/api/stop-capture?sessionId="+id, nil))
	s.wg.Wait()
	if w.Code != 200 || s.ownedLive.Error != "" || s.ownedLive.Packets == nil || *s.ownedLive.Packets == 0 {
		t.Fatalf("stop %d; capture %+v", w.Code, s.ownedLive)
	}
	t.Logf("finalized %d loopback packets", *s.ownedLive.Packets)
}
