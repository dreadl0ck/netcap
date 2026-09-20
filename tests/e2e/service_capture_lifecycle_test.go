//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestServiceCaptureLifecycle(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	build := exec.Command("go", "build", "-tags=nodpi", "-o", binary, "./cmd/")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build service binary: %v\n%s", err, output)
	}

	pcapPath := filepath.Join(temp, "input.pcap")
	writeTestPCAP(t, pcapPath)
	addr := freeLoopbackAddress(t)
	dataDir := filepath.Join(temp, "service-data")
	logFile, err := os.Create(filepath.Join(temp, "service.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	cmd := exec.Command(binary,
		"capture", "--service", "--dev",
		"--http", addr,
		"--service-data-dir", dataDir,
		"--service-max-per-hour", "4",
		"--workers", "2",
	)
	cmd.Dir = root
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	var serviceErr error
	go func() {
		serviceErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		select {
		case <-exited:
			return
		default:
		}
		_ = cmd.Process.Kill()
		<-exited
	})

	baseURL := "http://" + addr
	waitForService(t, baseURL+"/health", exited, logFile.Name())

	sessionIDs := make([]string, 0, 2)
	for range 2 {
		sessionID := uploadPCAP(t, baseURL+"/api/upload", pcapPath)
		waitForCompletion(t, baseURL+"/api/progress/"+sessionID, sessionID, logFile.Name())
		assertAuditOutput(t, filepath.Join(dataDir, "results", sessionID))
		sessionIDs = append(sessionIDs, sessionID)
	}
	if sessionIDs[0] == sessionIDs[1] {
		t.Fatalf("repeated uploads returned the same session ID %q", sessionIDs[0])
	}
	assertCompletedSessions(t, baseURL+"/api/try/sessions", sessionIDs)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal service: %v", err)
	}
	select {
	case <-exited:
		if serviceErr != nil {
			t.Fatalf("service shutdown: %v\n%s", serviceErr, readLog(logFile.Name()))
		}
	case <-time.After(40 * time.Second):
		t.Fatalf("service did not shut down cleanly\n%s", readLog(logFile.Name()))
	}
}

func writeTestPCAP(t *testing.T, path string) {
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
	for i := range 3 {
		buf := gopacket.NewSerializeBuffer()
		ip := &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
			SrcIP: net.IPv4(192, 0, 2, byte(i+1)), DstIP: net.IPv4(198, 51, 100, 1),
		}
		udp := &layers.UDP{SrcPort: layers.UDPPort(12000 + i), DstPort: 53}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			&layers.Ethernet{
				SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, byte(i + 1)},
				DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 1, 1}, EthernetType: layers.EthernetTypeIPv4,
			},
			ip, udp, gopacket.Payload([]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(data), Length: len(data),
		}, data); err != nil {
			t.Fatal(err)
		}
	}
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func waitForService(t *testing.T, url string, exited <-chan struct{}, logPath string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("service exited before becoming healthy\n%s", readLog(logPath))
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("service did not become healthy\n%s", readLog(logPath))
}

func uploadPCAP(t *testing.T, url, path string) string {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(part, f); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status %s: %s", resp.Status, responseBody)
	}
	var result struct {
		Success   bool   `json:"success"`
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.SessionID == "" {
		t.Fatalf("invalid upload response: %s", responseBody)
	}
	return result.SessionID
}

func waitForCompletion(t *testing.T, url, sessionID, logPath string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			var progress struct {
				Status          string  `json:"status"`
				ProgressPercent float64 `json:"progressPercent"`
				ErrorMessage    string  `json:"errorMessage"`
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&progress)
			_ = resp.Body.Close()
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			switch progress.Status {
			case "completed":
				if progress.ProgressPercent != 100 {
					t.Fatalf("session %s completed at %.1f%%", sessionID, progress.ProgressPercent)
				}
				return
			case "failed":
				t.Fatalf("session %s failed: %s\n%s", sessionID, progress.ErrorMessage, readLog(logPath))
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("session %s did not complete\n%s", sessionID, readLog(logPath))
}

func assertAuditOutput(t *testing.T, dir string) {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".ncap") && !strings.HasSuffix(entry.Name(), ".ncap.gz")) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no non-empty audit output in %s", dir)
	}
}

func assertCompletedSessions(t *testing.T, url string, want []string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Sessions []struct {
			SessionID    string `json:"sessionId"`
			Status       string `json:"status"`
			ResultsReady bool   `json:"resultsReady"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]struct {
		Status       string
		ResultsReady bool
	}, len(result.Sessions))
	for _, session := range result.Sessions {
		byID[session.SessionID] = struct {
			Status       string
			ResultsReady bool
		}{session.Status, session.ResultsReady}
	}
	for _, id := range want {
		session, ok := byID[id]
		if !ok || session.Status != "completed" || !session.ResultsReady {
			t.Errorf("session %s = %+v, found=%t", id, session, ok)
		}
	}
}

func readLog(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("read service log: %v", err)
	}
	return string(data)
}
