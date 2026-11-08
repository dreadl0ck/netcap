package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
)

func TestPacketPipelineChecksumConfig(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, bad := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict=%t/bad=%t", strict, bad), func(t *testing.T) {
				c := rawPacketCollector(1, 4, gopacket.Default)
				c.config.DecoderConfig = &config.Config{Checksum: strict}
				ip := rawPacketFixture(t, true, 80)[14:]
				parts := [][]byte{testutil.Fragment(ip, 73, 0, 16, true), testutil.Fragment(ip, 73, 16, len(ip)-20, false)}
				for i, part := range parts {
					part[10], part[11] = 0, 0
					binary.BigEndian.PutUint16(part[10:12], gopacket.FoldChecksum(gopacket.ComputeChecksum(part[:20], 0)))
					if bad && i == 1 {
						part[10] ^= 1
					}
					raw := testutil.Ethernet(part)
					if !c.submitPacket(testutil.Packet(raw, 0, uint64(i+1)), false) {
						t.Fatal("capture not admitted")
					}
					work := (<-c.workers[0]).(*packetWork)
					c.wg.Done()
					if !bytes.Equal(work.views.Original.Data(), raw) || len(work.views.Evidence) != 1 {
						t.Fatal("worker lost original fragment audit")
					}
					wantTransport := i == 1 && !(strict && bad)
					if (work.views.Packet != nil) != wantTransport {
						t.Fatalf("worker transport admission: %+v", work.views)
					}
				}
				stats := c.PacketPipelineStats()
				if strict && bad {
					if stats.RejectedIPv4Checksums != 1 || stats.Completed != 0 {
						t.Fatalf("checksum rejection unreported: %+v", stats)
					}
				} else if stats.Completed != 1 || stats.RejectedIPv4Checksums != 0 {
					t.Fatalf("valid/tolerant admission failed: %+v", stats)
				}
			})
		}
	}
}
