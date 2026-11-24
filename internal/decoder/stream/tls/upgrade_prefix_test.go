package tls

import (
	"bytes"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

type countedSource struct {
	core.SliceSource
	read *int
}

func (s countedSource) Walk(yield func(core.DataFragment) bool) error {
	return s.WalkRange(0, s.Count(), yield)
}
func (s countedSource) WalkRange(start, count int64, yield func(core.DataFragment) bool) error {
	return s.SliceSource.WalkRange(start, count, func(f core.DataFragment) bool { *s.read++; return yield(f) })
}

func TestUpgradePrefixStopsEachDirectionAtItsCap(t *testing.T) {
	var client, server core.SliceSource
	client = append(client, &core.StreamData{RawData: []byte("GET / HTTP/1.1\r\n\r\n"), Dir: reassembly.TCPDirClientToServer})
	for range 1000 {
		server = append(server, &core.StreamData{RawData: bytes.Repeat([]byte("b"), 1024), Dir: reassembly.TCPDirServerToClient})
	}
	read := 0
	c := &core.ConversationInfo{ClientSource: countedSource{client, &read}, ServerSource: countedSource{server, &read}}
	c.Source = core.MergedSource{Client: c.ClientSource, Server: c.ServerSource}
	got := upgradePrefixSource(c)
	want := upgradePrefixSequence((&core.ConversationInfo{Data: append(append(core.DataFragments{}, client...), server...)}).Fragments())
	if !bytes.Equal(got[0], want[0]) || !bytes.Equal(got[1], want[1]) {
		t.Fatal("per-direction prefixes differ from the merged walk")
	}
	if read > 1+maxUpgradeBytes/1024 {
		t.Fatalf("read %d fragments for a %d byte prefix", read, maxUpgradeBytes)
	}
}
