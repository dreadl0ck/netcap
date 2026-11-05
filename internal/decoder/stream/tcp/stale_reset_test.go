package tcp

import (
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket/layers"
)

func TestStaleResetCannotClosePendingSYNWhenFSMErrorsIgnored(t *testing.T) {
	old := decoderconfig.Instance
	cfg := old.Clone()
	cfg.IgnoreFSMerr = true
	decoderconfig.Instance = cfg
	streamutils.Stats.Lock()
	reject, connections := streamutils.Stats.RejectFsm, streamutils.Stats.RejectConnFsm
	streamutils.Stats.Unlock()
	t.Cleanup(func() {
		decoderconfig.Instance = old
		streamutils.Stats.Lock()
		streamutils.Stats.RejectFsm, streamutils.Stats.RejectConnFsm = reject, connections
		streamutils.Stats.Unlock()
	})
	c := &tcpConnection{tcpstate: reassembly.NewTCPSimpleFSM(reassembly.TCPSimpleFSMOptions{}), optchecker: reassembly.NewTCPOptionCheck()}
	client, server := reassembly.TCPDirClientToServer, reassembly.TCPDirServerToClient
	if !c.Accept(&layers.TCP{SYN: true, Seq: 4156112108}, client, -1) {
		t.Fatal("SYN rejected")
	}
	if c.Accept(&layers.TCP{RST: true, Seq: 3846439041}, client, 4156112109) {
		t.Fatal("stale reset admitted")
	}
	if !c.Accept(&layers.TCP{SYN: true, Seq: 4156112108}, client, 4156112109) || !c.Accept(&layers.TCP{SYN: true, ACK: true, Seq: 163134552, Ack: 4156112109}, server, -1) {
		t.Fatal("pending handshake poisoned by stale reset")
	}
}
