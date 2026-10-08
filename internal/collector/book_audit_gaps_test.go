package collector

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type bookWireCount struct{ Packets, Bytes int64 }

// Independent packet ledger, not counters derived from Connection records.
func bookWireCounts(t *testing.T, input string) map[string]bookWireCount {
	t.Helper()
	r, f, err := OpenPCAP(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	result := map[string]bookWireCount{}
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		ip, ok := p.NetworkLayer().(*layers.IPv4)
		if !ok {
			t.Fatal("wire ledger expects IPv4 fixture")
		}
		key := ip.SrcIP.String() + "/" + ip.Protocol.String()
		c := result[key]
		c.Packets++
		c.Bytes += int64(ci.Length)
		result[key] = c
	}
	return result
}

func TestBookPacketVersusByteRanking(t *testing.T) {
	b, input := newBookCapture(t)
	for range 10 {
		b.udp("192.0.2.1", "198.51.100.1", 61000, 9999, []byte("small"))
	}
	b.udp("192.0.2.2", "198.51.100.1", 61001, 9999, []byte(strings.Repeat("L", 2000)))
	ledger := bookWireCounts(t, input)
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			bytes := bookFlow(t, out, "true", "srcIP")
			q := bytes.Query
			q.SortBy = "packets"
			packets, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), q)
			if err != nil {
				t.Fatal(err)
			}
			if len(bytes.Groups) != 2 || len(packets.Groups) != 2 || bytes.Groups[0].Key != "192.0.2.2" || packets.Groups[0].Key != "192.0.2.1" {
				t.Fatalf("rankings do not discriminate bytes from packets: %+v / %+v", bytes.Groups, packets.Groups)
			}
			for _, g := range bytes.Groups {
				want := ledger[g.Key+"/UDP"]
				if g.Packets != want.Packets || g.Bytes != want.Bytes || len(g.Members) != 1 {
					t.Fatalf("ranked counters/reference differ from packet ledger: %+v", g)
				}
			}
		})
	}
}

func TestBookReadableC2Artifact(t *testing.T) {
	b, input := newBookCapture(t)
	command := "cat /lab/benign-report.txt\n"
	artifact := []byte("Synthetic lab report\nNo endpoint command was executed.\nmarker=NSM-READABLE-7421\n")
	b.conversation("192.0.2.10", "198.51.100.10", 62001, 6200, false, bookMessage{false, command}, bookMessage{true, string(artifact)})
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			m := bookStream(t, out, command, string(artifact))
			want := fmt.Sprintf("%x", sha256.Sum256(artifact))
			if m.Server.SHA256 != want || m.Server.Length != int64(len(artifact)) {
				t.Fatal("readable command output artifact changed")
			}
			connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
			if len(connections) != 1 || connections[0].CommunityID != m.CommunityID || connections[0].ObservationID == "" {
				t.Fatal("C2 artifact lacks session pivot")
			}
			var artifactPath string
			paths, err := filepath.Glob(filepath.Join(out, "stream-evidence", "*", "server.bin"))
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range paths {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) == string(artifact) {
					artifactPath = path
				}
			}
			if artifactPath == "" {
				t.Fatal("raw response file missing")
			}
			selected, err := evidence.ArchiveToFile(context.Background(), input, filepath.Join(out, "c2-packet-evidence.zip"), evidence.Selection{BPF: "tcp port 62001", MaxPackets: 100})
			if err != nil {
				t.Fatal(err)
			}
			if selected.Selected != 8 || selected.SourceSHA256 == "" || selected.OutputSHA256 == "" {
				t.Fatal("C2 artifact packet pivot incomplete")
			}
			rel, err := filepath.Rel(out, artifactPath)
			if err != nil {
				t.Fatal(err)
			}
			oracle := map[string]any{"command": command, "artifact": rel, "artifactSHA256": want, "connectionObservationID": connections[0].ObservationID, "connectionOrdinal": 0, "communityID": m.CommunityID, "packetSourceSHA256": selected.SourceSHA256, "endpointExecution": "not inferred; locally serialized fixture"}
			data, err := json.MarshalIndent(oracle, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "readable-c2-oracle.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}
