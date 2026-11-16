//go:build integration

package integration

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/dreadl0ck/netcap/types"
)

func TestRecheck168ForeignCapturesProduceNoProtobuf(t *testing.T) {
	for _, name := range []string{"nbns_refresh_fp.pcap", "nbns_query_fp.pcap", "dns_query_fp.pcap", "dns_response_fp.pcap"} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			if err := processWithCollector(testutil.Recheck168Capture(t, name), out); err != nil {
				t.Fatal(err)
			}
			udp, err := netio.Open(filepath.Join(out, "UDP.ncap.gz"), 4096)
			if err != nil {
				t.Fatal("control packets were not decoded", err)
			}
			if _, err := udp.ReadHeader(); err != nil {
				t.Fatal(err)
			}
			count := 0
			for {
				err := udp.Next(new(types.UDP))
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
			}
			udp.Close()
			if count == 0 {
				t.Fatal("empty UDP control")
			}
			path := filepath.Join(out, "Protobuf.ncap.gz")
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return
			}
			rows, err := readProtobufRecords(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Fatalf("foreign capture produced %d Protobuf records", len(rows))
			}
		})
	}
}
