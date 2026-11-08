package dcerpc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// D2-2: opt-in, immutable upstream captures, read only in memory. No files are carved.
// NETCAP_SMB_CORPUS=1 GOWORK=off GOMAXPROCS=2 go test -p 1 -tags nodpi,noyara,nomagika ./internal/decoder/stream/dcerpc -run TestSMBPinnedCorpus -v
func TestSMBPinnedCorpus(t *testing.T) {
	if os.Getenv("NETCAP_SMB_CORPUS") != "1" {
		t.Skip("set NETCAP_SMB_CORPUS=1 to fetch 2.8 MB of pinned Suricata captures")
	}
	const base = "https://raw.githubusercontent.com/OISF/suricata-verify/9a9178a7e4d45ff1d990e8f178c1e2f54b772f39/tests/"
	for _, tc := range []struct {
		path, hash                 string
		records, requests, replies int
	}{
		{"dcerpc-smb-test-01/input.pcap", "de72cf1bbd1809656766119870a2457dc44b292721b434be63613f0a6f7ae37c", 40, 18, 18},
		{"filestore-filecontainer-smb/filecontainer-smb.pcap", "248ca906c8677df97a4aeffdac483f00cbd5322493f7dcaf792a15cd89cb0b46", 3181, 1137, 1141},
	} {
		t.Run(tc.path, func(t *testing.T) {
			client := &http.Client{Timeout: 30 * time.Second}
			r, err := client.Get(base + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			if err != nil || r.StatusCode != 200 || fmt.Sprintf("%x", sha256.Sum256(data)) != tc.hash {
				t.Fatalf("fixture status=%d hash=%x error=%v", r.StatusCode, sha256.Sum256(data), err)
			}
			convs := smbCorpusConversations(t, data)
			counts := map[string]int{}
			pipes, records := 0, 0
			for _, c := range convs {
				for _, pipe := range smbPipeConversations(c) {
					pipes++
					for _, rec := range decodeAll(pipe) {
						records++
						counts[rec.InterfaceName+"/"+rec.PacketTypeName]++
						if rec.Timestamp == 0 || (rec.PacketType == 0 && rec.SrcIP != c.ClientIP) || (rec.PacketType == 2 && rec.SrcIP != c.ServerIP) {
							t.Fatalf("timestamp or direction lost: %+v", rec)
						}
					}
				}
			}
			t.Logf("flows=%d pipes=%d records=%d semantics=%v", len(convs), pipes, records, counts)
			if records != tc.records || counts["SVCCTL/Request"] != tc.requests || counts["SVCCTL/Response"] != tc.replies {
				t.Fatal("RPC PDU or bound SVCCTL request/response regression (D2-2)")
			}
		})
	}
}

// These fixtures have ordered TCP payloads. Reject holes rather than silently
// turning this transport-level replay into a second TCP reassembly implementation.
func smbCorpusConversations(t *testing.T, data []byte) []*core.ConversationInfo {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	type flow struct {
		c    *core.ConversationInfo
		next [2]uint32
		seen [2]bool
	}
	flows := map[string]*flow{}
	var result []*core.ConversationInfo
	for {
		b, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(b, r.LinkType(), gopacket.Default)
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 || (tcp.SrcPort != 445 && tcp.DstPort != 445 && tcp.SrcPort != 139 && tcp.DstPort != 139) {
			continue
		}
		client, server := packet.NetworkLayer().NetworkFlow().Endpoints()
		cp, sp, side := tcp.SrcPort, tcp.DstPort, 0
		dir := reassembly.TCPDirClientToServer
		if cp == 445 || cp == 139 {
			client, server, cp, sp, side, dir = server, client, sp, cp, 1, reassembly.TCPDirServerToClient
		}
		key := fmt.Sprintf("%s:%d->%s:%d", client, cp, server, sp)
		f := flows[key]
		if f == nil {
			f = &flow{c: &core.ConversationInfo{Ident: key, ClientIP: client.String(), ServerIP: server.String(), ClientPort: int32(cp), ServerPort: int32(sp)}}
			flows[key] = f
			result = append(result, f.c)
		}
		payload := tcp.Payload
		if f.seen[side] {
			delta := int32(tcp.Seq - f.next[side])
			if delta > 0 {
				t.Fatalf("fixture TCP hole/out-of-order in %s: %d bytes", key, delta)
			}
			if delta < 0 {
				overlap := -int64(delta)
				if overlap >= int64(len(payload)) {
					continue
				}
				payload = payload[overlap:]
			}
		}
		f.next[side], f.seen[side] = tcp.Seq+uint32(len(tcp.Payload)), true
		f.c.Data = append(f.c.Data, &core.StreamData{RawData: payload, Dir: dir, CaptureInformation: ci})
	}
	return result
}
