//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

const offlineFixtureNs int64 = 1700000000123456789

func TestOfflineRulesCLI(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	cacheCtx, cacheCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cacheCancel()
	cacheOutput, err := exec.CommandContext(cacheCtx, "go", "env", "-json", "GOCACHE", "GOMODCACHE", "GOPATH").Output()
	if err != nil {
		t.Fatalf("locate installed Go caches: %v", err)
	}
	var caches map[string]string
	if err := json.Unmarshal(cacheOutput, &caches); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(temp, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	// Keep toolchain discovery, but exclude inherited NC_ flags and credentials.
	env := []string{"HOME=" + home, "USERPROFILE=" + home, "NC_CONFIG_ROOT=" + filepath.Join(temp, "config"), "GOWORK=off", "CGO_ENABLED=1"}
	for key, value := range caches {
		env = append(env, key+"="+value)
	}
	for _, key := range []string{"PATH", "TMPDIR", "SystemRoot", "SDKROOT", "DEVELOPER_DIR", "PKG_CONFIG_PATH", "GOTOOLCHAIN", "GOFLAGS"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	binary := filepath.Join(temp, "net")
	buildCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net/")
	build.Dir, build.Env = root, env
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qualification binary: %v\n%s", err, output)
	}
	run := func(t *testing.T, args ...string) ([]byte, []byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir, cmd.Env = temp, env
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("child deadline (%v): %v\nstdout: %s\nstderr: %s", args, ctx.Err(), stdout.Bytes(), stderr.Bytes())
		}
		return stdout.Bytes(), stderr.Bytes(), err
	}
	pack := filepath.Join(temp, "grouped.yaml")
	offlineCLIWrite(t, pack, []byte(`format: netcap-offline-rules/v1
rules:
  - id: syn
    name: Grouped SYN
    type: TCP
    expression: SYN && !ACK
    severity: high
    enabled: true
    threshold:
      count: 50
      window: 600s
      group_by: [SrcIP, DstIP, DstPort]
`))
	if _, err := rules.LoadOfflinePack(pack); err != nil {
		t.Fatal(err)
	}
	capture := func(t *testing.T, pcap string, workers int, extra ...string) (string, evidence.CaptureManifest) {
		t.Helper()
		out := t.TempDir()
		args := []string{"capture", "-read", pcap, "-out", out, "-workers", strconv.Itoa(workers), "-include", "TCP", "-context=true", "-capture-evidence=true", "-bpf", "", "-dpi=false", "-geoDB=false", "-network-detection=false", "-quiet", "-http", "", "-compress=false"}
		args = append(args, extra...)
		stdout, stderr, err := run(t, args...)
		if err != nil {
			t.Fatalf("capture: %v\n%s\n%s", err, stdout, stderr)
		}
		var m evidence.CaptureManifest
		offlineCLIReadJSON(t, filepath.Join(out, "capture-manifest.json"), &m)
		var ready rules.OfflineReadyMarker
		offlineCLIReadJSON(t, filepath.Join(out, rules.OfflineReadyFile), &ready)
		if m.Version != 1 || m.RunID == "" || m.Status != "done" || m.Error != "" || ready.Version != 1 || ready.RunID != m.RunID {
			t.Fatalf("capture not finalized: manifest=%+v ready=%+v", m, ready)
		}
		if m.Config.Kind != "file" || m.Config.BPF != "" || m.Config.Workers != workers || m.CommunityScopes == nil || !m.CommunityScopes.Complete || m.CommunityScopes.Overflow != 0 {
			t.Fatalf("capture scope/config: %+v", m)
		}
		return out, m
	}
	parseReport := func(t *testing.T, out string, stdout, stderr []byte) rules.OfflineReport {
		t.Helper()
		// Decode exactly one report; never search backwards through nested braces.
		var report rules.OfflineReport
		decoder := json.NewDecoder(bytes.NewReader(stdout))
		if err := decoder.Decode(&report); err != nil {
			t.Fatalf("report JSON: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			t.Fatalf("unexpected output after report: %v: %s", err, stdout)
		}
		var persisted rules.OfflineReport
		offlineCLIReadJSON(t, filepath.Join(out, "rule-evaluations", report.ID+".json"), &persisted)
		if !reflect.DeepEqual(report, persisted) {
			t.Fatal("CLI report differs from durable report")
		}
		return report
	}
	evaluate := func(t *testing.T, out string) rules.OfflineReport {
		t.Helper()
		stdout, stderr, err := run(t, "investigate", "rules", "-read", out, "-rules", pack)
		if err != nil {
			t.Fatalf("evaluate: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}
		return parseReport(t, out, stdout, stderr)
	}
	assertReport := func(t *testing.T, out string, m evidence.CaptureManifest, count int64, packets int) rules.OfflineReport {
		t.Helper()
		r := evaluate(t, out)
		if r.Version != 1 || r.RunID != m.RunID || r.Status != "complete" || r.Error != "" || r.CommittedAlerts != count || r.PlannedAlerts != count || len(r.InputCanonicalDigest) != 64 || len(r.Rules) != 1 || r.Rules[0].Matches != int64(packets) || len(r.Types) != 1 || r.Types[0].Records != int64(packets) || r.Types[0].UnknownScopes != 0 {
			t.Fatalf("qualification report: %+v", r)
		}
		return r
	}
	for _, fixture := range []struct {
		name   string
		groups []int
		alerts int64
	}{
		{"same-source-50", []int{50}, 1},
		{"split-source-25-25", []int{25, 25}, 0},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			pcap := filepath.Join(t.TempDir(), "syn.pcap")
			offlineCLIPCAP(t, pcap, fixture.groups)
			var canonical, eventID string
			for _, workers := range []int{1, 2, 4, 8} {
				t.Run(fmt.Sprintf("workers-%d", workers), func(t *testing.T) {
					out, m := capture(t, pcap, workers)
					records := offlineCLITCP(t, out, m, 50)
					r := assertReport(t, out, m, fixture.alerts, len(records))
					alerts := offlineCLIAlerts(t, out)
					if int64(len(alerts)) != fixture.alerts {
						t.Fatalf("got %d alert records, want %d", len(alerts), fixture.alerts)
					}
					if canonical != "" && canonical != r.InputCanonicalDigest {
						t.Fatal("canonical input changed with worker count")
					}
					canonical = r.InputCanonicalDigest
					if len(alerts) == 0 {
						return
					}
					a := alerts[0]
					var envelope map[string]rules.OfflineAlertMetadata
					if err := json.Unmarshal([]byte(a.Notes), &envelope); err != nil {
						t.Fatal(err)
					}
					n := envelope["netcapOffline"]
					group := map[string]any{"SrcIP": "192.0.2.1", "DstIP": "198.51.100.1", "DstPort": map[string]any{"type": "int32", "value": "80"}}
					if len(envelope) != 1 || n.Version != 1 || n.RunID != m.RunID || n.RuleID != "syn" || n.RuleDigest != a.RuleDigest || n.InputCanonicalDigest != canonical || n.Count != 50 || n.First != offlineFixtureNs || n.Last != offlineFixtureNs+49*int64(time.Second) || n.WindowNs != int64(600*time.Second) || !reflect.DeepEqual(n.Group, group) || len(n.EventID) != 64 || len(n.Contributors) != 16 || !n.ContributorsTruncated {
						t.Fatalf("alert Notes: %s", a.Notes)
					}
					if a.Timestamp != n.Last || a.CommunityID == "" {
						t.Fatalf("trigger identity: %+v", a)
					}
					var trigger types.TCP
					if err := json.Unmarshal([]byte(a.MatchedRecord), &trigger); err != nil {
						t.Fatal(err)
					}
					if trigger.CommunityID != a.CommunityID || trigger.Timestamp != n.Last || trigger.SrcPort != 12049 || trigger.SrcIP != "192.0.2.1" {
						t.Fatalf("alert does not identify captured trigger: %+v", trigger)
					}
					found := false
					for _, entry := range m.CommunityScopes.Entries {
						found = found || entry.CommunityID == trigger.CommunityID && !entry.Ambiguous
					}
					if !found {
						t.Fatal("alert trigger Community ID absent from finalized run scope")
					}
					if eventID != "" && eventID != n.EventID {
						t.Fatal("event ID changed with worker count")
					}
					eventID = n.EventID
				})
			}
		})
	}
	t.Run("independent-captures-do-not-accumulate", func(t *testing.T) {
		pcap := filepath.Join(t.TempDir(), "syn.pcap")
		offlineCLIPCAP(t, pcap, []int{25})
		var previous string
		for range 2 {
			out, m := capture(t, pcap, 4)
			offlineCLITCP(t, out, m, 25)
			assertReport(t, out, m, 0, 25)
			if len(offlineCLIAlerts(t, out)) != 0 || m.RunID == previous {
				t.Fatal("independent capture state leaked")
			}
			previous = m.RunID
		}
	})
	t.Run("cli-api-equivalence", func(t *testing.T) {
		t.Setenv("HOME", home)
		t.Setenv("NC_CONFIG_ROOT", filepath.Join(temp, "api-config"))
		pcap := filepath.Join(t.TempDir(), "syn.pcap")
		offlineCLIPCAP(t, pcap, []int{50})
		out, m := capture(t, pcap, 4)
		offlineCLITCP(t, out, m, 50)
		cliReport := assertReport(t, out, m, 1, 50)
		cliAlerts := offlineCLIAlerts(t, out)
		addr := freeLoopbackAddress(t)
		server := webui.NewServer(addr, out, []string{pcap}, "", false, false, false, nil, nil, true)
		server.SetFileOutputDir(pcap, out)
		server.MarkFileCompleted(pcap)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Stop(ctx); err != nil {
				t.Errorf("stop API server: %v", err)
			}
		})
		yaml, err := os.ReadFile(pack)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]string{"yaml": string(yaml), "inputFile": pcap})
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Timeout: 30 * time.Second}
		response, err := client.Post("http://"+addr+"/api/rules/offline/execute", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("API evaluation: status=%s err=%v body=%s", response.Status, err, data)
		}
		var result struct {
			Report rules.OfflineReport `json:"report"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		apiReport := result.Report
		if apiReport.ID == cliReport.ID || apiReport.RunID != cliReport.RunID || apiReport.Status != "complete" || apiReport.Error != "" || apiReport.CommittedAlerts != 1 || apiReport.PlannedAlerts != 1 || apiReport.InputCanonicalDigest != cliReport.InputCanonicalDigest || apiReport.ConfigDigest != cliReport.ConfigDigest || apiReport.PackDigest != cliReport.PackDigest || !reflect.DeepEqual(apiReport.Types, cliReport.Types) || !reflect.DeepEqual(apiReport.Rules, cliReport.Rules) {
			t.Fatalf("CLI/API reports differ: cli=%+v api=%+v", cliReport, apiReport)
		}
		alerts := offlineCLIAlerts(t, out)
		if len(cliAlerts) != 1 || len(alerts) != 2 || alerts[0].Notes != alerts[1].Notes || alerts[0].MatchedRecord != alerts[1].MatchedRecord || alerts[0].CommunityID != alerts[1].CommunityID {
			t.Fatalf("CLI/API emitted different evidence: %+v", alerts)
		}
		var persisted rules.OfflineReport
		offlineCLIReadJSON(t, filepath.Join(out, "rule-evaluations", apiReport.ID+".json"), &persisted)
		if !reflect.DeepEqual(apiReport, persisted) {
			t.Fatal("API report differs from durable report")
		}
	})
	t.Run("capture-refuses-offline-pack", func(t *testing.T) {
		pcap := filepath.Join(t.TempDir(), "syn.pcap")
		offlineCLIPCAP(t, pcap, []int{50})
		out := t.TempDir()
		stdout, stderr, err := run(t, "capture", "-read", pcap, "-out", out, "-rules", pack, "-dpi=false", "-geoDB=false", "-network-detection=false", "-http", "", "-quiet")
		message := strings.ToLower(string(stdout) + string(stderr))
		if err == nil || !strings.Contains(message, "offline rule packs cannot be loaded by the live engine") {
			t.Fatalf("offline pack must be refused by capture: %v\n%s\n%s", err, stdout, stderr)
		}
		if len(offlineCLIAlerts(t, out)) != 0 {
			t.Fatal("refused offline pack emitted alerts")
		}
	})
	t.Run("truncated-audit-fails-without-alerts", func(t *testing.T) {
		pcap := filepath.Join(t.TempDir(), "syn.pcap")
		offlineCLIPCAP(t, pcap, []int{50, 25, 25})
		out, m := capture(t, pcap, 4)
		offlineCLITCP(t, out, m, 100)
		path := filepath.Join(out, "TCP.ncap")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, info.Size()-1); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := run(t, "investigate", "rules", "-read", out, "-rules", pack)
		if err == nil || !strings.Contains(string(stdout)+string(stderr), "TCP.ncap") || len(offlineCLIAlerts(t, out)) != 0 {
			t.Fatalf("corrupt audit accepted or emitted alerts: %v\n%s\n%s", err, stdout, stderr)
		}
	})
	t.Run("withheld-record-type-is-explicitly-partial", func(t *testing.T) {
		pcap := filepath.Join(t.TempDir(), "syn.pcap")
		offlineCLIPCAP(t, pcap, []int{50})
		out, m := capture(t, pcap, 2, "-include", "UDP")
		stdout, stderr, err := run(t, "investigate", "rules", "-read", out, "-rules", pack)
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || !strings.Contains(string(stderr), "incomplete coverage") {
			t.Fatalf("partial evaluation must exit nonzero with coverage diagnostic: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}
		r := parseReport(t, out, stdout, stderr)
		if r.Status != "partial" || r.RunID != m.RunID || r.CommittedAlerts != 0 || r.PlannedAlerts != 0 || len(r.Types) != 1 || r.Types[0].Type != "TCP" || !r.Types[0].Missing || len(offlineCLIAlerts(t, out)) != 0 {
			t.Fatalf("withheld TCP must be explicit: %+v", r)
		}
	})
}

func offlineCLIWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func offlineCLIReadJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, value); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func offlineCLIPCAP(t *testing.T, path string, groups []int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ordinal := 0
	for group, count := range groups {
		for range count {
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, byte(group+1)), DstIP: net.IPv4(198, 51, 100, 1)}
			tcp := &layers.TCP{SrcPort: layers.TCPPort(12000 + ordinal), DstPort: 80, SYN: true, Seq: uint32(ordinal + 1), Window: 4096}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp); err != nil {
				t.Fatal(err)
			}
			data := buf.Bytes()
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(0, offlineFixtureNs+int64(ordinal)*int64(time.Second)), CaptureLength: len(data), Length: len(data)}, data); err != nil {
				t.Fatal(err)
			}
			ordinal++
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func offlineCLIRecords(t *testing.T, path string, typ types.Type, newRecord func() proto.Message) []proto.Message {
	t.Helper()
	r, err := netio.Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h, err := r.ReadHeader()
	if err != nil || h.Type != typ {
		t.Fatalf("audit header %s: %+v %v", path, h, err)
	}
	var records []proto.Message
	for {
		record := newRecord()
		if err := r.Next(record); err != nil {
			if errors.Is(err, io.EOF) {
				return records
			}
			t.Fatalf("read %s: %v", path, err)
		}
		records = append(records, record)
	}
}

func offlineCLITCP(t *testing.T, out string, m evidence.CaptureManifest, count int) []*types.TCP {
	t.Helper()
	rows := offlineCLIRecords(t, filepath.Join(out, "TCP.ncap"), types.Type_NC_TCP, func() proto.Message { return &types.TCP{} })
	if len(rows) != count || m.IngressPackets != uint64(count) || m.AdmittedPackets != uint64(count) || m.QueueDrops != 0 || len(m.CommunityScopes.Entries) != count {
		t.Fatalf("capture lost packets/scopes: records=%d manifest=%+v", len(rows), m)
	}
	scopes := make(map[string]evidence.CommunityScope)
	for _, entry := range m.CommunityScopes.Entries {
		scopes[entry.CommunityID] = entry
	}
	ports := make(map[int32]bool)
	records := make([]*types.TCP, 0, count)
	for _, row := range rows {
		r := row.(*types.TCP)
		scope, ok := scopes[r.CommunityID]
		if !r.SYN || r.ACK || r.DstPort != 80 || r.Timestamp < offlineFixtureNs || r.Timestamp > offlineFixtureNs+int64(count-1)*int64(time.Second) || ports[r.SrcPort] || r.CommunityID == "" || !ok || scope.Ambiguous || scope.Scope.Sensor != "local" || scope.Scope.InterfaceIndex != 0 || len(scope.Scope.VLANs) != 0 {
			t.Fatalf("decoded TCP or run-qualified scope: %+v scope=%+v", r, scope)
		}
		ports[r.SrcPort] = true
		records = append(records, r)
	}
	return records
}

func offlineCLIAlerts(t *testing.T, out string) []*types.Alert {
	t.Helper()
	var alerts []*types.Alert
	for _, name := range []string{"Alert.ncap", "Alert.ncap.gz"} {
		path := filepath.Join(out, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		rows := offlineCLIRecords(t, path, types.Type_NC_Alert, func() proto.Message { return &types.Alert{} })
		for _, row := range rows {
			alerts = append(alerts, row.(*types.Alert))
		}
	}
	return alerts
}
