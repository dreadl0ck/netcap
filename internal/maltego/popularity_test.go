package maltego

import (
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"os"
	"path/filepath"
	"testing"
)

func TestIncomingOutgoingPopularityCounters(t *testing.T) {
	oldPath, oldConfig := resolvers.DataBaseFolderPath, resolvers.CurrentConfig
	t.Cleanup(func() {
		resolvers.DataBaseFolderPath, resolvers.CurrentConfig = oldPath, oldConfig
		resolvers.InitDNSWhitelist()
	})
	root := t.TempDir()
	resolvers.DataBaseFolderPath = root
	if err := os.WriteFile(filepath.Join(root, "hosts"), []byte("192.0.2.1\tWWW.EXAMPLE.CO.UK.\n192.0.2.2\tbob.github.io\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolvers.InitLocalDNS()
	list := filepath.Join(t.TempDir(), "list.csv")
	if err := os.WriteFile(list, []byte("1,example.co.uk\n2,alice.github.io\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolvers.CurrentConfig = resolvers.Config{DomainPopularityList: list}
	resolvers.InitDNSWhitelist()
	for _, incoming := range []bool{false, true} {
		for _, peer := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
			conn := &types.Connection{SrcIP: "198.51.100.1", DstIP: peer, TotalSize: 42}
			counter := CountOutgoingConnBytesFiltered
			if incoming {
				conn.SrcIP, conn.DstIP = conn.DstIP, conn.SrcIP
				counter = CountIncomingConnBytesFiltered
			}
			var min, max uint64
			var sizes []int
			counter(conn, "198.51.100.1", &min, &max, &sizes)
			if (len(sizes) == 0) != (peer == "192.0.2.1") {
				t.Fatalf("incoming=%v peer=%s sizes=%v", incoming, peer, sizes)
			}
		}
	}
}
