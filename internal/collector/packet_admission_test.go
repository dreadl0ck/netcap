package collector

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"
)

func admissionTestCollector(buffer int) *Collector {
	return &Collector{
		numWorkers:       1,
		workers:          []chan gopacket.Packet{make(chan gopacket.Packet, buffer)},
		acceptingPackets: true,
		log:              zap.NewNop(),
	}
}

func admissionTestPacket() gopacket.Packet {
	return gopacket.NewPacket([]byte{0}, gopacket.LayerTypePayload, gopacket.Default)
}

func TestPacketAdmissionClosesBeforeWorkerSentinel(t *testing.T) {
	c := admissionTestCollector(1)
	first := admissionTestPacket()
	second := admissionTestPacket()
	if !c.handlePacket(first) {
		t.Fatal("packet was rejected while admission was open")
	}

	dispatched := make(chan bool)
	go func() {
		dispatched <- c.handlePacket(second)
	}()
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt64(&c.current) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("second dispatch did not block on the full packet buffer")
		}
		runtime.Gosched()
	}

	shutdownStarted := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		close(shutdownStarted)
		c.closePacketAdmission()
		c.stopWorkers()
		close(shutdownDone)
	}()
	<-shutdownStarted

	if got := <-c.workers[0]; got != first {
		t.Fatalf("first queued value = %v, want packet", got)
	}
	c.wg.Done()
	if !<-dispatched {
		t.Fatal("packet queued before admission closure was rejected")
	}
	if got := <-c.workers[0]; got != second {
		t.Fatalf("second queued value = %v, want packet", got)
	}
	c.wg.Done()
	if got := <-c.workers[0]; got != nil {
		t.Fatalf("third queued value = %v, want worker sentinel", got)
	}
	<-shutdownDone
	c.wg.Wait()
}

func TestPacketAdmissionRejectsAfterShutdown(t *testing.T) {
	c := admissionTestCollector(1)
	c.closePacketAdmission()

	if c.handlePacket(admissionTestPacket()) {
		t.Fatal("packet was accepted after admission closed")
	}
	if got := atomic.LoadInt64(&c.current); got != 0 {
		t.Fatalf("accepted packet count = %d, want 0", got)
	}
	if got := len(c.workers[0]); got != 0 {
		t.Fatalf("queued packets = %d, want 0", got)
	}

	waited := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("rejected packet changed the wait group")
	}
}

func TestConcurrentDispatchAndShutdownProcessesAcceptedPacketsOnce(t *testing.T) {
	const dispatchers = 128
	c := admissionTestCollector(dispatchers)
	if !c.handlePacket(admissionTestPacket()) {
		t.Fatal("initial packet was rejected while admission was open")
	}

	var processed atomic.Int64
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for p := range c.workers[0] {
			if p == nil {
				return
			}
			processed.Add(1)
			c.wg.Done()
		}
	}()

	start := make(chan struct{})
	var producers sync.WaitGroup
	var accepted atomic.Int64
	accepted.Store(1)
	producers.Add(dispatchers)
	for range dispatchers {
		go func() {
			defer producers.Done()
			<-start
			if c.handlePacket(admissionTestPacket()) {
				accepted.Add(1)
			}
		}()
	}

	close(start)
	c.closePacketAdmission()
	c.stopWorkers()
	producers.Wait()
	c.wg.Wait()
	<-workerDone

	if got, want := processed.Load(), accepted.Load(); got != want {
		t.Fatalf("processed packets = %d, accepted %d", got, want)
	}
	if got, want := atomic.LoadInt64(&c.current), accepted.Load(); got != want {
		t.Fatalf("accepted packet count = %d, want %d", got, want)
	}
}
