package stream_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// Opt-in pinned replays. W76_NET is built with the same tags as
// the test; W76_REPRO_DIR contains the files in testdata/round2-selection.json.
func TestRound2PinnedCLIReplays(t *testing.T) {
	dir, binary := os.Getenv("W76_REPRO_DIR"), os.Getenv("W76_NET")
	if dir == "" || binary == "" {
		t.Skip("set W76_REPRO_DIR and W76_NET for pinned CLI replays")
	}
	var fixtures []struct {
		File, SHA256 string
		Have, Absent []string
	}
	manifest, err := os.ReadFile("testdata/round2-selection.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(manifest, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.File, func(t *testing.T) {
			input := filepath.Join(dir, fixture.File)
			data, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(data)) != fixture.SHA256 {
				t.Fatal("fixture SHA-256 mismatch")
			}
			if filepath.Ext(input) != ".pcap" && filepath.Ext(input) != ".pcapng" {
				input = filepath.Join(t.TempDir(), "input.pcap")
				if err := os.WriteFile(input, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var baseline map[string]int
			for _, workers := range []string{"default", "1", "2"} {
				t.Run(workers, func(t *testing.T) {
					out := t.TempDir()
					args := []string{"capture", "--read", input, "--out", out, "--quiet", "--fileStorage", ""}
					if workers != "default" {
						args = append(args, "--workers", workers, "--stream-workers", workers)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					if output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput(); err != nil {
						t.Fatalf("capture failed: %v\n%s", err, output)
					}
					counts := map[string]int{}
					makers := map[string]func() proto.Message{
						"HTTP": func() proto.Message { return &types.HTTP{} }, "DNS": func() proto.Message { return &types.DNS{} },
						"SMB": func() proto.Message { return &types.SMB{} }, "PROFINET": func() proto.Message { return &types.PROFINET{} },
						"RDP": func() proto.Message { return &types.RDP{} }, "S7Comm": func() proto.Message { return &types.S7Comm{} },
						"Modbus": func() proto.Message { return &types.Modbus{} }, "FTP": func() proto.Message { return &types.FTP{} },
						"Kerberos": func() proto.Message { return &types.Kerberos{} }, "Secret": func() proto.Message { return &types.Secret{} },
					}
					ftpID, ftpSecretID, axfrID := "", "", ""
					for name, makeRecord := range makers {
						path := filepath.Join(out, name+".ncap.gz")
						if _, err := os.Stat(path); os.IsNotExist(err) {
							continue
						}
						r, err := netio.Open(path, defaults.BufferSize)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := r.ReadHeader(); err != nil {
							t.Fatal(err)
						}
						for {
							m := makeRecord()
							if err := r.Next(m); err == io.EOF {
								break
							} else if err != nil {
								t.Fatal(err)
							}
							if name != "Secret" {
								counts[name]++
							}
							switch record := m.(type) {
							case *types.Secret:
								if strings.HasPrefix(record.Service, "TeamViewer") {
									counts["TeamViewer"]++
								}
								if record.Service == "FTP" && strings.Contains(record.Flow, ":8884") {
									counts["FTPSecret"]++
									ftpSecretID = record.CommunityID
									if record.Timestamp != 1240198113724062000 || record.User == "" || record.Password == "" || !record.AuthSuccessSet || !record.AuthSuccess {
										t.Error("FTP login lost capture timestamp, credentials or success response")
									}
								}
							case *types.FTP:
								if record.DstPort == 8884 && record.Command == "USER" {
									ftpID = record.CommunityID
								}
							case *types.HTTP:
								if fixture.File == "http-multiple100.pcap" && record.Method == "POST" {
									counts["Upload"]++
									if record.URL != "/upload" || record.ReqContentLength != 34498 || record.Timestamp != 1675839256835059000 || record.SrcIP != "10.25.17.47" || record.DstPort != 1551 || record.CommunityID == "" {
										t.Error("HTTP upload lost request semantics")
									}
								}
							case *types.DNS:
								if fixture.File == "dns_axfr.pcapng" {
									if len(record.Questions) != 1 || record.Questions[0].Type != 252 || record.CommunityID == "" {
										t.Error("AXFR question/correlation lost")
									}
									if axfrID != "" && record.CommunityID != axfrID {
										t.Error("AXFR directions have different Community IDs")
									}
									axfrID = record.CommunityID
								}
							}
						}
						_ = r.Close()
					}
					for _, name := range fixture.Have {
						if counts[name] == 0 {
							t.Errorf("missing %s", name)
						}
					}
					for _, name := range fixture.Absent {
						if counts[name] != 0 {
							t.Errorf("unexpected %s: %d", name, counts[name])
						}
					}
					if fixture.File == "http-multiple100.pcap" && counts["Upload"] == 0 {
						t.Error("missing POST upload")
					}
					if fixture.File == "dns_axfr.pcapng" && counts["DNS"] != 2 {
						t.Error("AXFR must retain query and response")
					}
					if fixture.File == "attack-trace.pcap_" && (counts["FTPSecret"] != 1 || ftpID == "" || ftpID != ftpSecretID) {
						t.Error("FTP secret duplicated or not correlated with control conversation")
					}
					if baseline == nil {
						baseline = counts
					} else if !reflect.DeepEqual(baseline, counts) {
						t.Errorf("worker-dependent records: %v != %v", counts, baseline)
					}
					t.Logf("records: %v", counts)
				})
			}
		})
	}
}
