package networkdetect

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestOriginalStaleProbeReplay(t *testing.T) {
	for _, tc := range []struct {
		env, digest string
		count       int
		frames      map[int]uint32
	}{
		{"NETCAP_H17_JUNE", "902c9f31e78ceb9a28519c6499d07db0901d535df2a4a8b005c8a598ddb08e77", 46937, map[int]uint32{14627: 3642540861}},
		{"NETCAP_H17_APRIL", "498ffc6e11fa8b38c07202a6fcb44da2a1064e9f89f6f8516b2985b08532f5e7", 57430, map[int]uint32{23822: 3660710524, 51004: 1080053869}},
	} {
		t.Run(tc.env, func(t *testing.T) {
			path := os.Getenv(tc.env)
			if path == "" {
				t.Skip("set " + tc.env + " to the pinned original capture")
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			hash := sha256.New()
			n, err := io.Copy(hash, io.LimitReader(f, 100<<20))
			if err != nil || n >= 100<<20 || fmt.Sprintf("%x", hash.Sum(nil)) != tc.digest {
				t.Fatal("unexpected original capture digest", err)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			reader, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := New(DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			ordinal := 0
			var reportedCandidates uint64
			checkAlerts := func(alerts []*types.Alert) {
				for _, alert := range alerts {
					_, note, qualified := strings.Cut(alert.Notes, "; possibleStaleProbeCandidates=")
					if !qualified {
						continue
					}
					var count uint64
					if _, err := fmt.Sscanf(note, "%d (intent and acceptance unknown)", &count); err != nil || count == 0 || alert.Name != "tcp.overlap-conflict" || alert.Severity != "medium" || count > alert.Count {
						t.Fatalf("invalid published stale-probe evidence: %v", alert)
					}
					reportedCandidates += count
				}
			}
			for {
				raw, ci, err := reader.ZeroCopyReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				ordinal++
				pkt := gopacket.NewPacket(raw, reader.LinkType(), gopacket.NoCopy)
				pkt.Metadata().CaptureInfo = ci
				matched := false
				for _, ev := range PacketEvents(pkt, Scope{Sensor: "original-replay", Interface: "capture"}) {
					before := engine.stats.ConflictingOverlapBytes
					candidates := engine.stats.StaleProbeCandidates
					alerts, err := engine.Observe(ev)
					if err != nil {
						t.Fatalf("frame %d: %v", ordinal, err)
					}
					checkAlerts(alerts)
					if seq, ok := tc.frames[ordinal]; ok && ev.Kind == "data" && ev.Seq == seq && ev.KeepAliveEligible && len(ev.Payload) == 1 && ev.Payload[0] == 0 {
						matched = true
						if engine.stats.ConflictingOverlapBytes-before != 1 {
							t.Errorf("frame %d did not retain its conflict byte", ordinal)
						}
						if engine.stats.StaleProbeCandidates-candidates != 1 {
							t.Errorf("frame %d lacks a stale-probe qualification", ordinal)
						}
					}
				}
				if _, ok := tc.frames[ordinal]; ok && !matched {
					t.Errorf("frame %d lost its probe evidence", ordinal)
				}
			}
			if ordinal != tc.count {
				t.Fatalf("processed %d packets, want %d", ordinal, tc.count)
			}
			checkAlerts(engine.Flush())
			if want := engine.Stats().StaleProbeCandidates; reportedCandidates != want {
				t.Fatalf("published %d stale-probe candidates, engine observed %d", reportedCandidates, want)
			}
			t.Logf("published %d stale-probe candidates in %d frames", reportedCandidates, ordinal)
		})
	}
}
