package tcp

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"testing"
)

func TestServicePrefixSegmentationAndGaps(t *testing.T) {
	banner := []byte("SSH-2.0-NetcapFixture_1.0\r\n")
	e := servicesignatures.Builtin()
	for split := 1; split < len(banner); split++ {
		first := &core.StreamData{RawData: banner[:split]}
		last := &core.StreamData{RawData: banner[split:]}
		fragments := core.DataFragments{first, last}
		if _, ok := e.Identify(contiguousServicePrefix(fragments, 512), "tcp", "server-to-client"); !ok {
			t.Fatalf("split %d lost", split)
		}
		for _, gap := range []int{-1, 1, 10} {
			broken := core.DataFragments{first, &core.StreamData{SkippedBytes: gap}, last}
			if _, ok := e.Identify(contiguousServicePrefix(broken, 512), "tcp", "server-to-client"); ok {
				t.Fatalf("split %d gap %d matched", split, gap)
			}
		}
	}
	if got := contiguousServicePrefix(core.DataFragments{&core.StreamData{RawData: banner}}, 4); string(got) != "SSH-" {
		t.Fatalf("bound: %q", got)
	}
	if got := contiguousServicePrefix(core.DataFragments{&core.StreamData{RawData: banner}}, -1); len(got) != 0 {
		t.Fatal("negative bound")
	}
}
