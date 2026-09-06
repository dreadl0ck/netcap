package collector

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/reassembly"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type lifecyclePacket struct {
	gopacket.Packet
	disposed atomic.Int32
	entered  chan struct{}
	release  chan struct{}
}

func lifecycleInitCollector(t *testing.T) *Collector {
	t.Helper()
	c := New(Config{Workers: 2, PacketBufferSize: 2, NoSignalHandling: true, NoPrompt: true, BaseLayer: layers.LayerTypeEthernet,
		FreeOSMem: 1, DecoderConfig: &config.Config{Out: t.TempDir(), Quiet: true,
			Null: true, IncludeDecoders: "Ethernet", IgnoreDecoderInitErrors: true}})
	if err := c.initLogging(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	return c
}

type lifecycleBlockingWriter struct {
	entered, release chan struct{}
	once             sync.Once
}

func (w *lifecycleBlockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return len(p), nil
}

func TestCollectorFullInitStopBarrier(t *testing.T) {
	c := lifecycleInitCollector(t)
	c.config.NoSignalHandling = false
	w := &lifecycleBlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	c.netcapLog = log.New(w, "", 0)
	initialized := make(chan error, 1)
	go func() { initialized <- c.Init() }()
	<-w.entered // Init holds lifecycleMu, before starting decoder initializers.
	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned during full Init")
	case <-time.After(20 * time.Millisecond):
	}
	close(w.release)
	if err := <-initialized; err != nil {
		t.Fatal(err)
	}
	<-stopped
	if !c.initialized || c.netcapLogFile != nil || c.workers != nil || c.assemblers != nil {
		t.Fatal("initialization did not finish before resource teardown")
	}
	if err := c.Init(); !errors.Is(err, ErrStopped) {
		t.Fatalf("Init after Stop = %v", err)
	}
}

func TestCollectorStopBeforeFullInit(t *testing.T) {
	c := New(Config{Workers: 1, DecoderConfig: &config.Config{Out: t.TempDir()}})
	c.Stop()
	if err := c.Init(); !errors.Is(err, ErrStopped) {
		t.Fatalf("Init after Stop = %v", err)
	}
	if c.netcapLogFile != nil || c.initialized || len(c.workers) != 0 {
		t.Fatal("stopped collector allocated initialization resources")
	}
}

func TestCollectorStopJoinsBlockedProducer(t *testing.T) {
	c := New(Config{Workers: 1, DecoderConfig: &config.Config{}})
	c.initWorkers()
	ctx, finish, err := c.beginCapture()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := net.Pipe()
	defer writer.Close()
	readStarted, interrupted, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		defer c.cleanup(false)
		defer finish()
		defer reader.Close()
		defer interruptCapture(ctx, context.Background(), func() { _ = reader.Close() })()
		close(readStarted)
		_, _ = reader.Read(make([]byte, 1))
		close(interrupted)
		<-release
		c.handlePacket(lifecyclePayload())
	}()
	<-readStarted
	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	<-interrupted
	select {
	case <-stopped:
		t.Fatal("Stop returned before the interrupted producer finished")
	default:
	}
	close(release)
	<-stopped
	<-exited // Producer-triggered cleanup must not wait on its own registration.
	if c.GetNumPackets() != 0 {
		t.Fatal("rejected producer packet changed counters")
	}
	if _, _, err := c.beginCapture(); !errors.Is(err, ErrStopped) {
		t.Fatal("producer registered after Stop")
	}
}

type lifecycleFlushDecoder struct {
	packet.DecoderAPI
	entered, release chan struct{}
	once             sync.Once
	destroyed        atomic.Bool
}

func (d *lifecycleFlushDecoder) FlushCurrentState() int64 {
	d.once.Do(func() { close(d.entered); <-d.release })
	return 0
}
func (d *lifecycleFlushDecoder) Destroy() (string, int64) { d.destroyed.Store(true); return "", 0 }
func (*lifecycleFlushDecoder) GetName() string            { return "lifecycle" }
func (*lifecycleFlushDecoder) NumRecords() int64          { return 0 }

func TestCollectorStopJoinsPeriodicFlush(t *testing.T) {
	c := lifecycleInitCollector(t)
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	d := &lifecycleFlushDecoder{entered: make(chan struct{}), release: make(chan struct{})}
	c.packetDecoders = append(c.packetDecoders, d)
	c.config.LiveFlushInterval = time.Millisecond
	stop := c.startPeriodicFlush()
	<-d.entered
	close(stop)
	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned during periodic flush")
	case <-time.After(20 * time.Millisecond):
	}
	if d.destroyed.Load() {
		t.Fatal("decoder destroyed during periodic flush")
	}
	close(d.release)
	<-stopped
	if !d.destroyed.Load() {
		t.Fatal("decoder not destroyed after periodic flush joined")
	}
}

func TestCollectorStopJoinsProgress(t *testing.T) {
	c := lifecycleInitCollector(t)
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.log = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(io.Discard), zap.DebugLevel),
		zap.Hooks(func(e zapcore.Entry) error {
			if strings.HasPrefix(e.Message, "decoding packets") {
				once.Do(func() { close(entered); <-release })
			}
			return nil
		}))
	c.config.DecoderConfig.PrintProgress = true
	c.statsInterval = time.Millisecond
	stop := c.printProgressInterval()
	<-entered
	close(stop)
	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned during progress output")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-stopped
	// This access races an unjoined progress writer under the race detector.
	clear(c.pps)
	c.pps[time.Now()] = 1
}

func TestCollectorCaptureReturnBarrier(t *testing.T) {
	for _, format := range []string{"pcap", "pcapng", "bpf"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture."+format)
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			data := rawPacketFixture(t, false, 64)
			ci := gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), Length: len(data), CaptureLength: len(data)}
			if format != "pcapng" {
				w := pcapgo.NewWriter(f)
				if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
					t.Fatal(err)
				}
				for range 3 {
					if err := w.WritePacket(ci, data); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
				if err != nil {
					t.Fatal(err)
				}
				for range 3 {
					if err := w.WritePacket(ci, data); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Flush(); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			c := lifecycleInitCollector(t)
			c.statsInterval = time.Millisecond
			if format == "bpf" {
				err = c.CollectBPF(path, "udp")
			} else if format == "pcap" {
				err = c.CollectPcap(path)
			} else {
				err = c.CollectPcapNG(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.GetNumPackets() != 3 {
				t.Fatalf("admitted count = %d, want 3", c.GetNumPackets())
			}
			if !c.lifecycleStopped || c.netcapLogFile != nil {
				t.Fatal("capture returned before cleanup")
			}
			clear(c.pps)
		})
	}
}

func TestCollectorBackgroundRegistrationStopRace(t *testing.T) {
	c := New(Config{DecoderConfig: &config.Config{}})
	var callers sync.WaitGroup
	var active atomic.Int32
	for range 10 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for range 20 {
				c.startBackground(func(ctx context.Context) {
					active.Add(1)
					defer active.Add(-1)
					<-ctx.Done()
				})
			}
		}()
	}
	c.Stop()
	callers.Wait()
	if active.Load() != 0 {
		t.Fatal("background task outlived Stop")
	}
}

func TestCollectorCaptureParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	closed := make(chan struct{})
	join := interruptCapture(context.Background(), parent, func() { close(closed) })
	cancel()
	<-closed
	join()
}

func TestCollectorLiveReadTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, time.Hour, time.Millisecond} {
		c := New(Config{Timeout: timeout})
		got := c.liveReadTimeout()
		if got <= 0 || got > 100*time.Millisecond {
			t.Fatalf("timeout %v is not interruptible: %v", timeout, got)
		}
	}
}

func (p *lifecyclePacket) Dispose() {
	if p.entered != nil {
		close(p.entered)
		<-p.release
	}
	p.disposed.Add(1)
}

func lifecyclePayload() gopacket.Packet {
	return gopacket.NewPacket([]byte{1}, gopacket.LayerTypePayload, gopacket.Default)
}

func TestWorkerStopJoinsDisposalAndRejectsAdmission(t *testing.T) {
	c := New(Config{Workers: 2, PacketBufferSize: 4, DecoderConfig: &config.Config{}})
	c.initWorkers()
	p := &lifecyclePacket{Packet: lifecyclePayload(), entered: make(chan struct{}), release: make(chan struct{})}
	c.handlePacket(p)
	<-p.entered
	stopped := make(chan struct{})
	go func() { c.stopWorkers(); close(stopped) }()
	// Waiting for the dispatch lock establishes that stop has closed admission.
	for {
		c.dispatchMu.Lock()
		stopping := c.workersStopped
		c.dispatchMu.Unlock()
		if stopping {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-stopped:
		t.Fatal("stop returned before packet disposal")
	default:
	}
	rejected := &lifecyclePacket{Packet: lifecyclePayload()}
	if c.handlePacket(rejected) || rejected.disposed.Load() != 1 {
		t.Fatal("stopped admission did not dispose packet")
	}
	close(p.release)
	<-stopped
	c.stopWorkers()
	c.wg.Wait()
	if p.disposed.Load() != 1 {
		t.Fatal("accepted packet not disposed exactly once")
	}
}

func TestWorkerConcurrentAdmissionFlushAndStop(t *testing.T) {
	c := New(Config{Workers: 4, PacketBufferSize: 1, DecoderConfig: &config.Config{}})
	c.initWorkers()
	var callers sync.WaitGroup
	for range 8 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for range 50 {
				c.handlePacket(lifecyclePayload())
				c.FlushAssemblers()
			}
		}()
	}
	for range 4 {
		callers.Add(1)
		go func() { defer callers.Done(); c.stopWorkers() }()
	}
	callers.Wait()
	c.wg.Wait()
	c.FlushAssemblers()
}

func TestWorkerInitStopBarrier(t *testing.T) {
	for range 20 {
		c := New(Config{Workers: 2, DecoderConfig: &config.Config{}})
		var callers sync.WaitGroup
		callers.Add(2)
		go func() { defer callers.Done(); c.initWorkers() }()
		go func() { defer callers.Done(); c.Stop() }()
		callers.Wait()
		if c.initWorkers() != nil || c.handlePacket(lifecyclePayload()) {
			t.Fatal("workers restarted after stop")
		}
		c.stopWorkers()
	}
}

func TestWorkerAdmissionTimeoutDisposes(t *testing.T) {
	c := rawPacketCollector(1, 0, gopacket.Default)
	p := &lifecyclePacket{Packet: lifecyclePayload()}
	c.handlePacketTimeout(p)
	c.wg.Wait()
	if p.disposed.Load() != 1 || c.admittedPackets != 0 {
		t.Fatal("timed-out packet was not disposed or counted as admitted")
	}
}

func TestWorkerMaintenanceGlobalFIFO(t *testing.T) {
	c := rawPacketCollector(3, 10, gopacket.Default)
	c.config.ReassembleConnections = true
	c.config.DecoderConfig = &config.Config{FlushEvery: 2}
	ref := time.Unix(100, 0)
	for i := range 3 {
		p := lifecyclePayload()
		p.Metadata().CaptureInfo.Timestamp = ref.Add(time.Duration(i) * time.Second)
		c.handlePacket(p)
	}
	packets, controls := 0, 0
	for _, w := range c.workers {
		seenControl := false
		for len(w) > 0 {
			p := <-w
			if control, ok := p.(*workerControl); ok {
				if seenControl || control.all || !control.ref.Equal(ref.Add(time.Second)) {
					t.Fatalf("unexpected control: %+v", control)
				}
				seenControl = true
				controls++
			} else {
				if p.Metadata().Timestamp.Equal(ref.Add(2*time.Second)) != seenControl {
					t.Fatal("maintenance overtook earlier data or followed later data")
				}
				packets++
				c.wg.Done()
			}
		}
		if !seenControl {
			t.Fatal("idle worker missed maintenance")
		}
	}
	if packets != 3 || controls != 3 {
		t.Fatalf("packets=%d controls=%d", packets, controls)
	}
}

type lifecycleStream struct{ delivered atomic.Int32 }

type lifecycleContext struct{ timestamp time.Time }

func (c lifecycleContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: c.timestamp}
}

func (s *lifecycleStream) New(gopacket.Flow, gopacket.Flow, reassembly.AssemblerContext) reassembly.Stream {
	return s
}
func (*lifecycleStream) Accept(*layers.TCP, reassembly.TCPFlowDirection, reassembly.Sequence) bool {
	return true
}
func (s *lifecycleStream) ReassembledSG(reassembly.ScatterGather, reassembly.AssemblerContext) {
	s.delivered.Add(1)
}
func (*lifecycleStream) ReassemblyComplete(reassembly.AssemblerContext, gopacket.Flow, string) bool {
	return true
}

func TestWorkerMaintenanceFlushesIdlePools(t *testing.T) {
	c := New(Config{Workers: 3, PacketBufferSize: 4, ReassembleConnections: true,
		DecoderConfig: &config.Config{FlushEvery: 1, ClosePendingTimeOut: time.Minute, CloseInactiveTimeOut: time.Minute}})
	ref := time.Unix(100, 0)
	streams := make([]*lifecycleStream, 3)
	for i := range streams {
		streams[i] = &lifecycleStream{}
		a := reassembly.NewAssembler(reassembly.NewStreamPool(streams[i]))
		a.AssembleWithContext(gopacket.NewFlow(layers.EndpointIPv4, []byte{1, 2, 3, 4}, []byte{4, 3, 2, 1}),
			&layers.TCP{SrcPort: 1000, DstPort: 2000, SYN: true, Seq: 1}, lifecycleContext{ref})
		a.AssembleWithContext(gopacket.NewFlow(layers.EndpointIPv4, []byte{1, 2, 3, 4}, []byte{4, 3, 2, 1}),
			&layers.TCP{SrcPort: 1000, DstPort: 2000, ACK: true, Seq: 100, BaseLayer: layers.BaseLayer{Payload: []byte{1}}}, lifecycleContext{ref})
		streams[i].delivered.Store(0)
		c.assemblers = append(c.assemblers, a)
		c.workers = append(c.workers, c.worker(a))
	}
	c.numWorkers = len(c.workers)
	p := lifecyclePayload()
	p.Metadata().CaptureInfo.Timestamp = ref.Add(time.Hour)
	c.handlePacket(p)
	c.stopWorkers()
	for i, s := range streams {
		if s.delivered.Load() == 0 {
			t.Errorf("worker %d: idle stream pending data not flushed", i)
		}
	}
}

func TestWorkerPrivatePoolsAndLiveFlushReferences(t *testing.T) {
	c := New(Config{Workers: 3, DecoderConfig: &config.Config{}})
	c.initWorkers()
	defer c.stopWorkers()
	seen := make(map[uintptr]bool)
	for _, a := range c.assemblers {
		pool := reflect.ValueOf(a).Elem().FieldByName("connPool").Pointer()
		if pool == 0 || seen[pool] {
			t.Fatal("workers share a stream pool")
		}
		seen[pool] = true
	}
	before := append([]*reassembly.Assembler(nil), c.assemblers...)
	c.FlushAssemblers()
	if !reflect.DeepEqual(before, c.assemblers) {
		t.Fatal("live flush released assembler references")
	}
	if !c.handlePacket(lifecyclePayload()) {
		t.Fatal("live flush stopped admission")
	}
}
