package firewallstate

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestAuthoritativeClockRollbackDoesNotReopenWindows(t *testing.T) {
	cfg := stateConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Digest("revision"), Digest("group")}
	w := Window{Mode: "fixed", Duration: time.Second}
	start := time.Now()
	count := func(at time.Time, want int64) CountResult {
		t.Helper()
		v, e := s.Bind(testScope).Count(context.Background(), key, w, at)
		if e != nil || v.Count != want {
			t.Fatalf("at %v: %+v %v", at, v, e)
		}
		return v
	}
	count(start, 1)
	fresh := count(start.Add(2*time.Second), 1)
	rolled := count(start.Add(-time.Hour), 2)
	if !fresh.Expires.Equal(rolled.Expires) {
		t.Fatal("clock rollback shifted window expiry")
	}
	_ = s.Close()
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after := count(start, 3)
	if !after.Expires.Equal(fresh.Expires) {
		t.Fatal("restart lost clock high-water mark")
	}
	count(start.Add(3*time.Second), 1)
	if _, err = s.Bind(testScope).Count(context.Background(), key, w, time.Unix(0, math.MaxInt64)); err == nil {
		t.Fatal("overflow timestamp accepted")
	}
}
