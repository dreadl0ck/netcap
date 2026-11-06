package capture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap"
)

// Each command runs in a separate process: capture owns package-level decoder state.
func TestCPUProfileCommandProcess(t *testing.T) {
	if os.Getenv("NETCAP_PROFILE_HELPER") != "1" {
		return
	}
	args := strings.Split(os.Getenv("NETCAP_PROFILE_ARGS"), "\n")
	cmd := &cli.Command{Flags: GetFlags(), Action: RunWithContext}
	err := cmd.Run(context.Background(), append([]string{"capture"}, args...))
	if want := os.Getenv("NETCAP_PROFILE_ERROR"); want != "" {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want %q", err, want)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func runProfileCommand(t *testing.T, dir, wantErr string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCPUProfileCommandProcess$", "-test.v")
	cmd.Dir = dir
	// Avoid workstation NC_* settings changing this isolated replay.
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "NC_") && !strings.HasPrefix(e, "NETCAP_PROFILE_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "NETCAP_PROFILE_HELPER=1", "NETCAP_PROFILE_ARGS="+strings.Join(args, "\n"), "NETCAP_PROFILE_ERROR="+wantErr)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("command: %v\n%s", err, out)
	}
}

func readCPUProfile(t *testing.T, dir string) *profile.Profile {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "netcap-"+netcap.Version+".cpu.profile"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := profile.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckValid(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCPUProfileCommandReturns(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"missing", "expand input pattern", []string{"--read", "missing.pcap"}},
		{"malformed", "collect pcapng", []string{"--read", "bad.pcap"}},
		{"service", "unsupported", []string{"--service"}},
		{"upload", "unsupported", []string{"--http", "localhost:8080"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "bad.pcap"), []byte("bad"), 0600); err != nil {
				t.Fatal(err)
			}
			runProfileCommand(t, dir, tc.want, append([]string{"--cpuprof"}, tc.args...)...)
			if tc.want != "unsupported" {
				readCPUProfile(t, dir)
			} else {
				if _, err := os.Stat(filepath.Join(dir, "netcap-"+netcap.Version+".cpu.profile")); !os.IsNotExist(err) {
					t.Fatalf("unsupported mode created profile: %v", err)
				}
			}
		})
	}
}

func writeCPUReplay(t *testing.T, path string, count int) int {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 12346}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(make([]byte, 128))); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	for i := range count {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)*1000), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	return len(data)
}

func cpuReplayArgs(input, out string) []string {
	return []string{"--cpuprof", "--read", input, "--out", out,
		"--include", "Ethernet,IPv4,UDP", "--workers", "2", "--null", "--quiet", "--http-shutdown=false",
		"--dpi=false", "--macDB=false", "--ja4DB=false", "--serviceDB=false", "--geoDB=false", "--reverse-dns=false", "--local-dns=false",
		"--reassemble-connections=false", "--network-detection=false", "--flow-exports=false", "--capture-evidence=false", "--y"}
}

func TestCPUProfileMultipleInputs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"input1", "input2"} {
		writeCPUReplay(t, filepath.Join(dir, name+".pcap"), 2000)
	}
	runProfileCommand(t, dir, "", cpuReplayArgs("input*.pcap", filepath.Join(dir, "out"))...)
	readCPUProfile(t, dir)
	for _, name := range []string{"input1", "input2"} {
		b, err := os.ReadFile(filepath.Join(dir, "out", name, "performance.log"))
		if err != nil || !strings.Contains(string(b), "Total Packets:        2000") {
			t.Fatalf("%s report: %v\n%s", name, err, b)
		}
	}
}

func TestCPUProfileSamplesCaptureProcessing(t *testing.T) {
	// Increase only if the sampling clock missed the smaller deterministic replay.
	for _, count := range []int{100_000, 400_000, 1_200_000} {
		dir := t.TempDir()
		packetBytes := writeCPUReplay(t, filepath.Join(dir, "input.pcap"), count)
		runProfileCommand(t, dir, "", cpuReplayArgs("input.pcap", filepath.Join(dir, "out"))...)
		p := readCPUProfile(t, dir)
		report, err := os.ReadFile(filepath.Join(dir, "out", "performance.log"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(report), "Total Packets:        "+strconv.Itoa(count)) || !strings.Contains(string(report), "("+strconv.Itoa(count*packetBytes)+" bytes)") {
			t.Fatalf("incorrect admission report:\n%s", report)
		}
		for _, s := range p.Sample {
			positive := false
			for _, v := range s.Value {
				positive = positive || v > 0
			}
			if !positive {
				continue
			}
			for _, l := range s.Location {
				for _, line := range l.Line {
					if line.Function != nil && (strings.Contains(line.Function.Name, "internal/collector.(*Collector).worker") || strings.Contains(line.Function.Name, "internal/collector.(*Collector).submitPacket")) {
						t.Logf("%d packets: positive processing sample in %s", count, line.Function.Name)
						return
					}
				}
			}
		}
		t.Logf("%d packets: no capture worker/admission samples; increasing fixture", count)
	}
	t.Fatal("bounded replay ladder produced no positive capture-processing samples")
}
