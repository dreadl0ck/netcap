package collector

import (
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

// TestDNSTransactionsReplay checks capture-time DNS pairing on a real capture
// and that the result does not depend on the worker count.
func TestDNSTransactionsReplay(t *testing.T) {
	input := filepath.Join("..", "networkdetect", "testdata", "live", "dga.pcap")
	var reference []string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := t.TempDir()
			dc := config.DefaultConfig.Clone()
			dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,UDP,DNS", true
			c := New(Config{Workers: workers, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, ResolverConfig: resolvers.Config{}, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700})
			if err := c.CollectPcap(input); err != nil {
				t.Fatal(err)
			}
			r, err := netio.Open(filepath.Join(out, "DNS.ncap.gz"), 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := r.ReadHeader(); err != nil {
				t.Fatal(err)
			}
			var got []string
			counts := map[string]int{}
			for {
				var d types.DNS
				if err := r.Next(&d); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				counts[d.TransactionStatus]++
				if d.QR && d.TransactionStatus == "answered" && d.RTT <= 0 {
					t.Fatalf("answered response without RTT: %+v", d)
				}
				if !d.QR && d.RTT != 0 {
					t.Fatalf("query with RTT: %+v", d)
				}
				got = append(got, fmt.Sprintf("%d|%d|%t|%s|%d|%d", d.Timestamp, d.ID, d.QR, d.TransactionStatus, d.RTT, d.QueryTransmissions))
			}
			if counts["query"] == 0 || counts["answered"] == 0 {
				t.Fatalf("no paired transactions: %v", counts)
			}
			sort.Strings(got)
			if workers == 1 {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("worker count changed DNS pairing")
			}
		})
	}
}
