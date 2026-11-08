package collector

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"
)

func TestCaptureTimeIdleExpiryPrecedesAdvancingPacketAndIgnoresReplaySpeed(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 40000, 80, false)
	send(false, false, false, "GET /old HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	wire.offset = time.Minute
	send(false, false, false, "GET /new HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	watermark := send(true, false, false, "HTTP/1.1 404 Missing\r\nContent-Length: 0\r\n\r\n")
	wire.offset = 0
	wire.packet("203.0.113.1", "203.0.113.2", &layers.TCP{SrcPort: 41000, DstPort: 81, Seq: 1, ACK: true, Window: 4096}, "", false)
	var reference []string
	for _, workers := range []int{1, 4} {
		for _, pause := range []time.Duration{0, 5 * time.Millisecond} {
			t.Run(fmt.Sprintf("workers=%d/pause=%s", workers, pause), func(t *testing.T) {
				out := t.TempDir()
				cfg := ultimateCaptureConfig(out, workers, 0)
				cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
				cfg.DecoderConfig.CaptureTimeIdleExpiry = true
				cfg.DecoderConfig.ClosePendingTimeOut, cfg.DecoderConfig.CloseInactiveTimeOut = time.Second, time.Second
				cfg.DecoderConfig.RecordObserver = func(proto.Message) { time.Sleep(pause) }
				c := New(cfg)
				if err := c.CollectPcap(input); err != nil {
					t.Fatal(err)
				}
				rows := readIncrementalHTTP(t, out)
				if len(rows) != 2 {
					t.Fatal(rows)
				}
				var semantic []string
				for _, row := range rows {
					if row.URL == "/old" && row.StatusCode != 0 || row.URL == "/new" && row.StatusCode != 404 {
						t.Fatal("timeout ran after the future packet, or EOF was mistaken for idle expiry", row)
					}
					semantic = append(semantic, row.String())
				}
				sort.Strings(semantic)
				if reference == nil {
					reference = semantic
				} else if !reflect.DeepEqual(reference, semantic) {
					t.Fatal("workers/replay speed changed capture-time timeout semantics", semantic, reference)
				}
				health := bookJSON[struct {
					WatermarkNS string `json:"watermarkNs"`
					LatePackets uint64 `json:"latePackets"`
				}](t, filepath.Join(out, "CaptureTimeMaintenance.json"))
				if health.WatermarkNS != fmt.Sprint(watermark) || health.LatePackets != 1 {
					t.Fatal("late packet rewound event time", health)
				}
			})
		}
	}
	// Negative control: without opt-in expiry the old unanswered request owns
	// the response at EOF. This distinguishes an actual watermark from EOF sorting.
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 1, 0)
	cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
	c := New(cfg)
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	rows := readIncrementalHTTP(t, out)
	oldMatched := false
	for _, row := range rows {
		oldMatched = oldMatched || row.URL == "/old" && row.StatusCode == 404
	}
	if !oldMatched {
		t.Fatal("negative control did not expose completion-only correlation", rows)
	}
}

func TestCaptureTimeIdleExpiryRequiresBothDirectionsIdle(t *testing.T) {
	wire, input := newBookCapture(t)
	send := wire.openTCP("192.0.2.1", "198.51.100.1", 40000, 80, false)
	send(false, false, false, "GET /old HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	for _, offset := range []time.Duration{500 * time.Millisecond, time.Second, 1500 * time.Millisecond} {
		wire.offset = offset
		send(true, false, false, "")
	}
	wire.offset = 2 * time.Second
	send(false, false, false, "GET /new HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	send(true, false, false, "HTTP/1.1 404 Missing\r\nContent-Length: 0\r\n\r\n")
	for _, workers := range []int{1, 4} {
		out := t.TempDir()
		cfg := ultimateCaptureConfig(out, workers, 0)
		cfg.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
		cfg.DecoderConfig.CaptureTimeIdleExpiry = true
		cfg.DecoderConfig.ClosePendingTimeOut, cfg.DecoderConfig.CloseInactiveTimeOut = time.Second, time.Second
		if err := New(cfg).CollectPcap(input); err != nil {
			t.Fatal(err)
		}
		rows := readIncrementalHTTP(t, out)
		oldMatched := false
		for _, row := range rows {
			oldMatched = oldMatched || row.URL == "/old" && row.StatusCode == 404
		}
		if !oldMatched {
			t.Fatal("one quiet direction prematurely expired a live duplex stream", rows)
		}
	}
}
