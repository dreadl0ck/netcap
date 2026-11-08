package packetview_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
)

func fixIPChecksum(raw []byte) {
	raw[10], raw[11] = 0, 0
	binary.BigEndian.PutUint16(raw[10:12], gopacket.FoldChecksum(gopacket.ComputeChecksum(raw[:int(raw[0]&15)*4], 0)))
}

func TestFragmentIPv4Checksum(t *testing.T) {
	ip := testutil.TCP(false, false, 1, 0, "S", "checksum regression payload")
	// TCP checksum includes the IPv4 pseudoheader, independent of fragment headers.
	pseudo := append(append([]byte(nil), ip[12:20]...), 0, byte(layers.IPProtocolTCP), 0, byte(len(ip)-20))
	binary.BigEndian.PutUint16(ip[36:38], gopacket.FoldChecksum(gopacket.ComputeChecksum(append(pseudo, ip[20:]...), 0)))
	if gopacket.FoldChecksum(gopacket.ComputeChecksum(append(pseudo, ip[20:]...), 0)) != 0 {
		t.Fatal("fixture TCP checksum is invalid")
	}
	for _, strict := range []bool{false, true} {
		for _, bad := range []int{-1, 0, 1, 2} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("strict=%t/bad=%d/reverse=%t", strict, bad, reverse), func(t *testing.T) {
					p := packetview.New(packetview.Limits{Checksum: strict})
					parts := [][]byte{testutil.Fragment(ip, 42, 0, 16, true), testutil.Fragment(ip, 42, 16, len(ip)-20, false)}
					for _, part := range parts {
						fixIPChecksum(part)
					}
					if reverse {
						parts[0], parts[1] = parts[1], parts[0]
					}
					if bad == 2 {
						// Invalid exact duplicate must poison an already buffered set.
						parts = [][]byte{parts[0], append([]byte(nil), parts[0]...), parts[1]}
						parts[1][10] ^= 1
					} else if bad >= 0 {
						parts[bad][10] ^= 1
					}
					var completed gopacket.Packet
					for i, part := range parts {
						raw := testutil.Ethernet(part)
						r := p.Process(testutil.Packet(raw, 0, uint64(i+1)), uint64(i+1))
						if !bytes.Equal(r.Original.Data(), raw) || len(r.Evidence) != 1 || !bytes.Equal(r.Evidence[0].NetworkLayer().LayerContents(), part[:20]) {
							t.Fatal("original fragment evidence lost or rewritten")
						}
						if r.Packet != nil {
							completed = r.Packet
						}
						badIndex := bad
						if bad == 2 {
							badIndex = 1
						}
						if strict && bad >= 0 && i == badIndex && r.Status != "ipv4-checksum-rejected" {
							t.Fatalf("missing checksum qualification: %s", r.Status)
						}
					}
					if strict && bad >= 0 {
						if completed != nil || p.Stats().RejectedIPv4Checksums != 1 || p.Stats().Rejected != 1 || p.Stats().BufferedBytes != 0 {
							t.Fatalf("invalid set admitted or unreported: %+v", p.Stats())
						}
						for i, part := range parts {
							fixIPChecksum(part)
							if r := process(p, part, uint64(i+10)); r.Packet != nil || r.Status != "fragment-rejected" {
								t.Fatal("corrected retransmission escaped rejected-set quarantine")
							}
						}
					} else if completed == nil || !bytes.Equal(completed.TransportLayer().LayerContents(), ip[20:40]) || p.Stats().Completed != 1 {
						t.Fatalf("valid/tolerant reassembly changed: %+v", p.Stats())
					}
				})
			}
		}
	}
}

func TestChecksumLeavesNonfragmentAndAtomicPathsUnchanged(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		ip := testutil.TCP(v6, false, 1, 0, "S", "")
		inputs := [][]byte{ip}
		if v6 {
			inputs = append(inputs, testutil.Fragment(ip, 7, 0, len(ip)-40, false))
		}
		for _, raw := range inputs {
			a := process(packetview.New(packetview.Limits{}), raw, 1)
			b := process(packetview.New(packetview.Limits{Checksum: true}), raw, 1)
			if a.Status != b.Status || a.Packet == nil || b.Packet == nil || !bytes.Equal(a.Packet.Data(), b.Packet.Data()) || len(a.Evidence) != len(b.Evidence) {
				t.Fatal("checksum policy changed nonfragment/atomic normalization")
			}
		}
	}
}
