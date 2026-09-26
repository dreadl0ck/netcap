//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// The tracked Ultimate PCAP has 2,380 UDP/3389 packets dissected as RDP-UDP
// and TLS by Wireshark. An MQTT-SN length/type match in one encrypted datagram
// used to claim the entire conversation and emit thousands of bogus records.
func TestRDPUDPIsNotMQTTSN(t *testing.T) {
	pcap := filepath.Join("..", "The Ultimate PCAP v20260316.pcapng")
	if _, err := os.Stat(pcap); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := processWithCollector(pcap, out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "MQTTSN.ncap.gz")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	} else if err != nil {
		t.Fatal(err)
	}
	r, err := netio.Open(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	for {
		rec := &types.MQTTSN{}
		if err := r.Next(rec); err != nil {
			break
		}
		if rec.SrcPort == 3389 || rec.DstPort == 3389 {
			t.Fatalf("RDP-UDP on port 3389 was classified as MQTT-SN: %+v", rec)
		}
	}
}
