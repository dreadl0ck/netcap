package collector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"go.uber.org/zap"
)

func liveApplicationCollector(t *testing.T) *Collector {
	t.Helper()
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Quiet = t.TempDir(), true
	c := New(Config{DecoderConfig: dc, NetworkDetection: true})
	c.log = zap.NewNop()
	c.captureKind = "live"
	if err := c.initNetworkDetection(); err != nil {
		t.Fatal(err)
	}
	c.recordScopes[endpoints("192.0.2.1", 40000, "198.51.100.1", 80)] = recordScope{Scope: networkdetect.Scope{Sensor: "fixture", Interface: "live"}, Key: "fixture"}
	t.Cleanup(func() {
		if err := c.closeNetworkDetection(); err != nil {
			t.Error(err)
		}
		c.detachRecordAnalysis()
	})
	return c
}

func applicationHTTP(at int64, path string) *types.HTTP {
	return &types.HTTP{Timestamp: at, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", SrcPort: 40000, DstPort: 80, Method: "GET", URL: path, StatusCode: 404}
}

func readApplicationAlerts(t *testing.T, c *Collector) []*types.Alert {
	t.Helper()
	r, err := netio.Open(filepath.Join(c.config.DecoderConfig.Out, "Alert.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var rows []*types.Alert
	for {
		a := new(types.Alert)
		if err := r.Next(a); err == io.EOF {
			return rows
		} else if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, a)
	}
}

func TestLiveApplicationCheckpointBeforeClose(t *testing.T) {
	c := liveApplicationCollector(t)
	// A batch has deterministic capture-time order despite callback scheduling.
	for i := 31; i >= 0; i-- {
		c.observeDecodedRecord(applicationHTTP(int64(i)*1e9, fmt.Sprintf("/missing/%d", i)))
	}
	c.flushAllDecoders()
	rows := readApplicationAlerts(t, c)
	if len(rows) != 1 || rows[0].Name != "http.scan" || !strings.Contains(rows[0].Notes, "flush=live") {
		t.Fatal(rows)
	}
	if c.applicationRecords != nil || c.applicationQueuedBytes != 0 || c.applicationDetector.Late != 0 {
		t.Fatal("checkpoint retained observations or reordered capture time")
	}
	// Old completed connections cannot rewind the detector and silently alter history.
	c.observeDecodedRecord(applicationHTTP(1e9, "/late"))
	c.flushAllDecoders()
	c.flushAllDecoders()
	if c.applicationDetector.Late != 1 || len(readApplicationAlerts(t, c)) != 1 {
		t.Fatal("late observation was accepted or checkpoint duplicated an alert")
	}
	stats := c.networkDetector.Stats()
	c.applicationDetectionStats(&stats)
	if stats.ApplicationAlerts != 1 || stats.ApplicationLate != 1 || stats.ApplicationQueueLimit != maxApplicationQueueBytes || stats.ApplicationQueuedBytes != 0 {
		t.Fatal(stats)
	}
}

func TestLiveApplicationMaintenanceWithoutOutputSnapshots(t *testing.T) {
	c := liveApplicationCollector(t)
	c.acceptingPackets = true
	for i := 0; i < 32; i++ {
		c.observeDecodedRecord(applicationHTTP(int64(i)*1e9, fmt.Sprintf("/missing/%d", i)))
	}
	c.maintainStreams(time.Now())
	if c.applicationDetector.Alerts != 1 || c.applicationQueuedBytes != 0 || c.networkDetectionError != nil {
		t.Fatal("maintenance did not drain application evidence", c.networkDetectionError)
	}
}

func TestLiveApplicationMissingnessDoesNotBecomeScan(t *testing.T) {
	for _, qualification := range []string{"gap", "locally-truncated", "response-not-observed"} {
		t.Run(qualification, func(t *testing.T) {
			c := liveApplicationCollector(t)
			for i := 0; i < 32; i++ {
				r := applicationHTTP(int64(i)*1e9, fmt.Sprintf("/missing/%d", i))
				r.ReassemblyStatus = qualification
				c.observeDecodedRecord(r)
			}
			c.flushAllDecoders()
			if c.applicationDetector.Alerts != 0 {
				t.Fatal("qualified observations counted as complete failed transactions")
			}
		})
	}
}

func TestApplicationQueueBudgetSharedAndReusable(t *testing.T) {
	c := liveApplicationCollector(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				c.observeDecodedRecord(applicationHTTP(1, strings.Repeat("x", 2048)))
			}
		}()
	}
	wg.Wait()
	if c.applicationQueuedBytes > maxApplicationQueueBytes || c.applicationQueueDrops == 0 || c.applicationQueuedBytes == 0 || len(c.applicationRecords) >= 100000 {
		t.Fatal("shared byte budget did not reject before record-count cap", c.applicationQueuedBytes, c.applicationQueueDrops)
	}
	c.flushAllDecoders()
	if c.applicationQueuedBytes != 0 || c.applicationRecords != nil {
		t.Fatal("consumed queue retained its reservation")
	}
	c.observeDecodedRecord(applicationHTTP(2, "/reused"))
	if c.applicationQueuedBytes == 0 || len(c.applicationRecords) != 1 {
		t.Fatal("budget could not be reused")
	}
}

func TestApplicationCheckpointWriterFailureCancelsCapture(t *testing.T) {
	dc := config.DefaultConfig.Clone()
	dc.Out = t.TempDir()
	c := New(Config{DecoderConfig: dc, NetworkDetection: true})
	c.captureKind = "live"
	ctx := c.contextLocked()
	if err := c.initNetworkDetection(); err != nil {
		t.Fatal(err)
	}
	defer c.detachRecordAnalysis()
	defer c.closeNetworkDetection()
	c.recordScopes[endpoints("192.0.2.1", 40000, "198.51.100.1", 80)] = recordScope{Scope: networkdetect.Scope{Sensor: "fixture", Interface: "live"}, Key: "fixture"}
	for i := 0; i < 32; i++ {
		c.observeDecodedRecord(applicationHTTP(int64(i)*1e9, fmt.Sprintf("/missing/%d", i)))
	}
	if err := c.networkAlertWriter.Close(); err != nil {
		t.Fatal(err)
	}
	c.checkpointNetworkDetection()
	if c.networkDetectionError == nil || ctx.Err() == nil || c.applicationQueuedBytes != 0 {
		t.Fatal("writer failure lost its error, cancellation, or reservation release")
	}
}

func TestApplicationWriterFailurePreventsAuditReadiness(t *testing.T) {
	wire, input := newBookCapture(t)
	wire.conversation("192.0.2.1", "198.51.100.1", 40000, 443, false, bookMessage{text: "GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n"}, bookMessage{server: true, text: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"})
	out := t.TempDir()
	configuration := ultimateCaptureConfig(out, 2, 0)
	configuration.CaptureEvidence, configuration.NetworkDetection = true, true
	configuration.DecoderConfig.IncludeDecoders = "TCP,Connection,HTTP"
	var c *Collector
	configuration.DecoderConfig.RecordObserver = func(m proto.Message) {
		if _, ok := m.(*types.HTTP); ok {
			_ = c.networkAlertWriter.Close()
		}
	}
	c = New(configuration)
	err := c.CollectPcap(input)
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
	if err == nil || manifest.Status != "error" || !os.IsNotExist(readyErr) || c.GetNetworkDetectionError() == nil {
		t.Fatal("failed application alert persistence became ready", err, manifest.Status, readyErr)
	}
}

func TestLiveApplicationCheckpointWaitsForEveryWorker(t *testing.T) {
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			c := liveApplicationCollector(t)
			gate, arrived := make(chan struct{}), make(chan struct{})
			for worker := range workers {
				queue := make(chan gopacket.Packet, 1)
				c.workers = append(c.workers, queue)
				go func() {
					control := (<-queue).(*workerControl)
					if worker == 0 {
						close(arrived)
						<-gate
					}
					for i := worker; i < 32; i += workers {
						c.observeDecodedRecord(applicationHTTP(int64(i)*1e9, fmt.Sprintf("/missing/%d", i)))
					}
					close(control.done)
				}()
			}
			done := make(chan struct{})
			go func() {
				c.dispatchMu.Lock()
				c.checkpointNetworkDetection()
				c.dispatchMu.Unlock()
				close(done)
			}()
			<-arrived
			select {
			case <-done:
				t.Fatal("checkpoint overtook an admitted worker")
			default:
			}
			close(gate)
			<-done
			c.workers = nil
			if c.applicationDetector.Alerts != 1 || c.applicationDetector.Late != 0 || c.applicationQueuedBytes != 0 {
				t.Fatal("worker scheduling changed application detection")
			}
		})
	}
}
