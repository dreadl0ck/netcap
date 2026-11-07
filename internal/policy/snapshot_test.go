package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestSnapshotRoundTripAllNativeState(t *testing.T) {
	for _, distinct := range []string{"", "Attributes.value"} {
		for _, mode := range []string{"fixed", "sliding"} {
			r := thresholdRule(mode, 3)
			r.Threshold.Distinct = distinct
			s := sequenceRule()
			s.Sequence.Window = "1m"
			c := compiled(t, bundle(r, s))
			now := time.Unix(100, 123456789)
			for _, e := range []Event{{Method: "POST", Path: "/login", Body: "private-body-marker", Attributes: map[string]string{"value": "private-identity-marker"}}, {Method: "POST", Attributes: map[string]string{"value": "second"}}} {
				if _, err := c.EvaluateAt(context.Background(), e, now); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := c.ExportState(context.Background())
			if err != nil {
				t.Fatal(mode, distinct, err)
			}
			if bytes.Contains(raw, []byte("private-body-marker")) || bytes.Contains(raw, []byte("private-identity-marker")) {
				t.Fatal("snapshot persisted event data")
			}
			fork := c.Fork()
			if err := fork.ImportState(context.Background(), raw); err != nil {
				t.Fatal(mode, distinct, err)
			}
			if fork.StateStats() != c.StateStats() || !fork.StateWatermark().Equal(now) {
				t.Fatal("restored metadata changed")
			}
			again, err := fork.ExportState(context.Background())
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("snapshot is not canonical", err)
			}
			for _, e := range []Event{{Method: "POST", Path: "/account", Attributes: map[string]string{"value": "third"}}, {Path: "/export"}} {
				d1, e1 := c.EvaluateAt(context.Background(), e, now.Add(time.Millisecond))
				d2, e2 := fork.EvaluateAt(context.Background(), e, now.Add(time.Millisecond))
				if e1 != nil || e2 != nil || d1.Verdict != d2.Verdict || d1.RuleID != d2.RuleID {
					t.Fatalf("restored semantics differ: %+v %+v %v %v", d1, d2, e1, e2)
				}
			}
		}
	}
}

func TestSnapshotCorruptionAndRollbackAreTransactional(t *testing.T) {
	c := compiled(t, bundle(thresholdRule("sliding", 3)))
	now := time.Unix(100, 0)
	_, err := c.EvaluateAt(context.Background(), Event{Method: "POST"}, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.ExportState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(raw); i++ {
		bad := append([]byte(nil), raw...)
		bad[i] ^= 0xff
		fork := c.Fork()
		err := fork.ImportState(context.Background(), bad)
		if err == nil || fork.StateStats() != (StateStats{}) {
			t.Fatalf("partial import at byte %d", i)
		}
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0), make([]byte, MaxSnapshotBytes+1)} {
		fork := c.Fork()
		if err := fork.ImportState(context.Background(), bad); err == nil || fork.StateStats() != (StateStats{}) {
			t.Fatal("malformed snapshot accepted", err)
		}
	}
	other := compiled(t, bundle(thresholdRule("fixed", 3)))
	if err := other.ImportState(context.Background(), raw); !errors.Is(err, ErrSnapshot) {
		t.Fatal("revision mismatch accepted", err)
	}
	if _, err := c.EvaluateAt(context.Background(), Event{Method: "POST"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	before := c.StateStats()
	if err := c.ImportState(context.Background(), raw); !errors.Is(err, ErrStateClock) || c.StateStats() != before {
		t.Fatal("older snapshot rewound live watermark", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Fork().ImportState(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSnapshotExpiresAtOriginalDeadline(t *testing.T) {
	c := compiled(t, bundle(thresholdRule("sliding", 2)))
	now := time.Unix(100, 0)
	_, _ = c.EvaluateAt(context.Background(), Event{Method: "POST"}, now)
	raw, err := c.ExportState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	restored := c.Fork()
	if err := restored.ImportState(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	d, err := restored.EvaluateAt(context.Background(), Event{Method: "POST"}, now.Add(10*time.Second))
	if err != nil || d.Verdict != "allow" {
		t.Fatal("restore extended expired sliding window", d, err)
	}
	if _, err := restored.EvaluateAt(context.Background(), Event{}, now); !errors.Is(err, ErrStateClock) {
		t.Fatal("authoritative clock reversal accepted", err)
	}
}

func TestSnapshotValidChecksumStillRequiresValidStructure(t *testing.T) {
	c := compiled(t, bundle(thresholdRule("sliding", 3)))
	now := time.Unix(100, 0)
	_, _ = c.EvaluateAt(context.Background(), Event{Method: "POST"}, now)
	raw, err := c.ExportState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	header := len(snapshotMagic) + 32 + 8 + 4
	name := header + 2
	kind := name + int(binary.BigEndian.Uint16(raw[header:header+2]))
	key := kind + 1
	token := key + 32
	expiry := token + 32
	count := expiry + 8
	step := count + 4
	payload := step + 2
	stamp := payload + 4
	for label, change := range map[string]func([]byte){
		"revision":  func(b []byte) { b[len(snapshotMagic)] ^= 1 },
		"watermark": func(b []byte) { binary.BigEndian.PutUint64(b[len(snapshotMagic)+32:], 0) },
		"groups":    func(b []byte) { binary.BigEndian.PutUint32(b[header-4:], MaxGroups+1) },
		"rule":      func(b []byte) { copy(b[name:name+4], "evil") },
		"kind":      func(b []byte) { b[kind] = 99 },
		"key":       func(b []byte) { b[key] ^= 1 },
		"token":     func(b []byte) { b[token] ^= 1 },
		"expiry":    func(b []byte) { binary.BigEndian.PutUint64(b[expiry:], uint64(now.Add(time.Hour).UnixNano())) },
		"count":     func(b []byte) { binary.BigEndian.PutUint32(b[count:], 1000001) },
		"step":      func(b []byte) { binary.BigEndian.PutUint16(b[step:], 1) },
		"payload":   func(b []byte) { binary.BigEndian.PutUint32(b[payload:], MaxStateEntries+1) },
		"timestamp": func(b []byte) { binary.BigEndian.PutUint64(b[stamp:], uint64(now.Add(time.Second).UnixNano())) },
	} {
		t.Run(label, func(t *testing.T) {
			bad := append([]byte(nil), raw...)
			change(bad)
			sum := sha256.Sum256(bad[:len(bad)-sha256.Size])
			copy(bad[len(bad)-sha256.Size:], sum[:])
			fork := c.Fork()
			if err := fork.ImportState(context.Background(), bad); err == nil || fork.StateStats() != (StateStats{}) {
				t.Fatal("invalid state accepted despite structural validation", err)
			}
		})
	}
	body := raw[:len(raw)-sha256.Size]
	duplicate := append([]byte(nil), body...)
	duplicate = append(duplicate, body[header:]...)
	binary.BigEndian.PutUint32(duplicate[header-4:], 2)
	sum := sha256.Sum256(duplicate)
	duplicate = append(duplicate, sum[:]...)
	if err := c.Fork().ImportState(context.Background(), duplicate); err == nil {
		t.Fatal("duplicate state key accepted")
	}
}
