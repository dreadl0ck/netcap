/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Package collector provides a mechanism to collect network packets from a network interface on macOS, linux and windows
package collector

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/evilsocket/islazy/tui"
	"github.com/gopacket/gopacket"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// errInvalidOutputDirectory indicates that a file path was supplied instead of a directory.
var errInvalidOutputDirectory = errors.New("expected a directory, but got a file for output path")

// headerPrinted tracks whether the netcap header has been printed to prevent duplicate headers
// when processing multiple input files
var (
	headerPrinted     bool
	headerPrintedLock sync.Mutex
)

// Collector provides an interface to collect data from PCAP or a network interface.
// this structure has an optimized field order to avoid excessive padding.
type Collector struct {
	mu                sync.Mutex
	statMutex         sync.Mutex
	current           int64
	numPacketsLast    int64
	totalBytesWritten int64
	numPackets        int64
	numWorkers        int
	workers           []chan gopacket.Packet
	start             time.Time

	// when running multiple epochs, the timestamp of the first run can be preserved.
	startFirst               time.Time
	assemblers               []*reassembly.Assembler
	goPacketDecoders         map[gopacket.LayerType][]*packet.GoPacketDecoder
	packetDecoders           []packet.DecoderAPI
	streamDecoders           []core.StreamDecoderAPI
	abstractDecoders         []core.DecoderAPI
	progressString           string
	next                     int
	unkownPcapWriterAtomic   *atomicPcapGoWriter
	unknownPcapFile          *os.File
	errorsPcapWriterBuffered *bufio.Writer
	errorsPcapWriterAtomic   *atomicPcapGoWriter
	errorsPcapFile           *os.File
	errorLogFile             *os.File
	unknownProtosAtomic      *decoderutils.AtomicCounterMap
	allProtosAtomic          *decoderutils.AtomicCounterMap
	files                    map[string]string
	inputSize                int64
	unkownPcapWriterBuffered *bufio.Writer
	config                   *Config
	errorMap                 *decoderutils.AtomicCounterMap
	wg                       sync.WaitGroup
	shutdown                 bool
	isLive                   bool

	// logging
	log           *zap.Logger // collector.log
	netcapLog     *log.Logger // netcap.log
	netcapLogFile *os.File

	zapLoggers     []*zap.Logger
	logFileHandles []*os.File

	InputFile string
	PrintTime bool
	Bpf       string

	Epochs    int
	numEpochs int

	// throughput measurements in timestamps mapped to packets per second values
	pps map[time.Time]float64

	// interval for tracking collector stats
	statsInterval time.Duration
}

// New returns a new Collector instance.
func New(config Config) *Collector {
	if config.OutDirPermission == 0 {
		config.OutDirPermission = defaults.DirectoryPermission
	}

	return &Collector{
		next:                1,
		unknownProtosAtomic: decoderutils.NewAtomicCounterMap(),
		allProtosAtomic:     decoderutils.NewAtomicCounterMap(),
		errorMap:            decoderutils.NewAtomicCounterMap(),
		files:               map[string]string{},
		config:              &config,
		start:               time.Now(),
		numEpochs:           1,
		pps:                 map[time.Time]float64{},
		statsInterval:       5 * time.Second,
	}
}

// stopWorkers halts all workers.
func (c *Collector) stopWorkers() {
	// wait until all packets have been decoded
	c.mu.Lock()
	for i, w := range c.workers {
		select {
		case w <- nil:
			c.log.Info("worker done", zap.Int("num", i))
			//case <-time.After(5 * time.Second):
			//	fmt.Println("worker", i, "seems stuck, skipping...")
		}
	}
	c.mu.Unlock()
}

// handleSignals catches signals and runs the cleanup
// SIGQUIT is not caught, to allow debugging by producing a stack and goroutine trace.
func (c *Collector) handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// start signal handler and cleanup routine
	go func() {
		sig := <-sigs

		c.printlnStdOut("\nreceived signal:", sig)
		c.printlnStdOut("exiting")
		c.log.Info("received signal", zap.String("sig", sig.String()))

		go func() {
			sign := <-sigs
			c.printlnStdOut("force quitting, signal:", sign)
			os.Exit(0)
		}()

		c.cleanup(true)
		os.Exit(0)
	}()

	if c.config.HTTPShutdownEndpoint {
		c.printlnStdOut("serving http shutdown endpoint")
		go c.serveCleanupHTTPEndpoint()
	}
}

func (c *Collector) serveCleanupHTTPEndpoint() {
	var (
		cleanupTriggered bool
		cleanupMu        sync.Mutex
	)

	http.HandleFunc("/cleanup", func(w http.ResponseWriter, r *http.Request) {
		var force bool

		// sync access
		cleanupMu.Lock()
		force = cleanupTriggered
		cleanupMu.Unlock()

		// second time cleanup request will force shutdown
		if force {
			c.log.Info("shutdown forced via local http endpoint from", zap.String("userAgent", r.UserAgent()), zap.String("addr", r.RemoteAddr))

			// triggered once already. now force shutdown
			c.printlnStdOut("force quitting")

			// reply OK
			// TODO: hold the connection open until the stream processing is going on.
			// This way the Stop command could flush the latest audit records to maltego once the netcap process exited.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))

			// do this in the background to allow the http request handler to finish cleanly
			go func() {
				time.Sleep(1 * time.Second)
				os.Exit(0)
			}()

			return
		}

		// first time shutdown triggered
		cleanupMu.Lock()
		cleanupTriggered = true
		cleanupMu.Unlock()

		c.log.Info("shutdown request received via local http endpoint from", zap.String("userAgent", r.UserAgent()), zap.String("addr", r.RemoteAddr))

		c.cleanup(true)

		// reply OK
		// TODO: hold the connection open until the stream processing is going on.
		// This way the Stop command could flush the latest audit records to maltego once the netcap process exited.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))

		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
	})

	err := http.ListenAndServe("127.0.0.1:60589", nil)
	if err != nil {
		log.Fatal(
			"failed to bind http shutdown endpoint:\n",
			err,
			"\n > This usually happens when multiple instances of NETCAP are running,",
			"\n > or another service is blocking port 60589.",
			"\n > Please quit all remaining NETCAP processes and try again.",
			"\n > Running multiple processes in parallel is currently not possible,",
			"\n > due to atomic access to the resolver bleve databases.",
		)
	}
}

// to decode incoming packets in parallel
// they are passed to several worker goroutines in round robin style.
func (c *Collector) handlePacket(p gopacket.Packet) {
	// make it work for 1 worker only, can be used for debugging
	if c.numWorkers == 1 {
		c.workers[0] <- p

		return
	}

	c.workers[c.next] <- p

	// increment or reset next
	if c.config.Workers == c.next+1 {
		// reset
		c.next = 0
	} else {
		c.next++
	}
}

// to decode incoming packets in parallel
// they are passed to several worker goroutines in round robin style.
func (c *Collector) handlePacketTimeout(p gopacket.Packet) {
	select {
	// send the packetInfo to the decoder routine
	case c.workers[c.next] <- p:
	case <-time.After(3 * time.Second):
		pkt := gopacket.NewPacket(p.Data(), c.config.BaseLayer, gopacket.Default)

		var (
			nf gopacket.Flow
			tf gopacket.Flow
		)

		if nl := pkt.NetworkLayer(); nl != nil {
			nf = nl.NetworkFlow()
		}

		if tl := pkt.TransportLayer(); tl != nil {
			tf = tl.TransportFlow()
		}

		fmt.Println("handle packet timeout", nf, tf)
	}

	// increment or reset next
	if c.config.Workers == c.next+1 {
		// reset
		c.next = 0
	} else {
		c.next++
	}
}

// print errors to stdout in red.
func (c *Collector) printErrors() {
	if c.config.DecoderConfig.Quiet {
		_, _ = fmt.Fprintln(c.netcapLogFile, c.getErrorSummary(), ansi.Reset)
	} else {
		_, _ = fmt.Println(ansi.Red, c.getErrorSummary(), ansi.Reset)
	}
}

// closes the logfile for errors.
func (c *Collector) closeErrorLogFile() {
	summary := c.getErrorSummary()

	c.mu.Lock()

	_, err := c.errorLogFile.WriteString(summary)
	if err != nil {
		c.log.Error("failed to write stats into error log", zap.Error(err))

		return
	}

	// sync
	err = c.errorLogFile.Sync()
	if err != nil {
		c.log.Error("failed to sync error log", zap.Error(err))

		return
	}

	// close file handle
	err = c.errorLogFile.Close()
	if err != nil {
		c.log.Error("failed to close error log", zap.Error(err))

		return
	}

	c.mu.Unlock()
}

// stats prints collector statistics.
func (c *Collector) stats() {
	var target io.Writer
	if c.config.DecoderConfig.Quiet {
		target = c.netcapLogFile
	} else {
		target = io.MultiWriter(os.Stderr, c.netcapLogFile)
	}

	var rows [][]string

	c.unknownProtosAtomic.Lock()

	for k, v := range c.allProtosAtomic.Items {
		// Skip records with 0 count
		if v == 0 {
			continue
		}

		if k == "Payload" {
			rows = append(rows, []string{k, fmt.Sprint(v), share(v, c.numPackets)})

			continue
		}

		if _, ok := c.unknownProtosAtomic.Items[k]; ok {
			rows = append(rows, []string{"*" + k, fmt.Sprint(v), share(v, c.numPackets)})
		} else {
			rows = append(rows, []string{k, fmt.Sprint(v), share(v, c.numPackets)})
		}
	}

	numUnknown := len(c.unknownProtosAtomic.Items)

	c.unknownProtosAtomic.Unlock()
	tui.Table(target, []string{"GoPacketDecoder", "NumRecords", "Share"}, rows)

	// print legend if there are unknown protos
	// -1 for "Payload" layer
	if numUnknown-1 > 0 {
		if !c.config.DecoderConfig.Quiet {
			fmt.Println("* protocol supported by gopacket, but not implemented in netcap")
		}
	}

	if len(c.packetDecoders) > 0 {
		rows = [][]string{}
		for _, d := range c.packetDecoders {
			// Skip records with 0 count
			if d.NumRecords() > 0 {
				rows = append(rows, []string{d.GetName(), strconv.FormatInt(d.NumRecords(), 10), share(d.NumRecords(), c.numPackets)})
			}
		}

		if len(rows) > 0 {
			tui.Table(target, []string{"PacketDecoder", "NumRecords", "Share"}, rows)
		}
	}

	if len(c.streamDecoders) > 0 {
		rows = [][]string{}
		for _, d := range c.streamDecoders {
			// Skip records with 0 count
			if d.NumRecords() > 0 {
				rows = append(rows, []string{d.GetName(), strconv.FormatInt(d.NumRecords(), 10), share(d.NumRecords(), c.numPackets)})
			}
		}

		if len(rows) > 0 {
			tui.Table(target, []string{"StreamDecoder", "NumRecords", "Share"}, rows)
		}
	}

	if len(c.abstractDecoders) > 0 {
		rows = [][]string{}
		for _, d := range c.abstractDecoders {
			// Skip records with 0 count
			if d.NumRecords() > 0 {
				rows = append(rows, []string{d.GetName(), strconv.FormatInt(d.NumRecords(), 10), share(d.NumRecords(), c.numPackets)})
			}
		}

		if len(rows) > 0 {
			tui.Table(target, []string{"AbstractDecoder", "NumRecords", "Share"}, rows)
		}
	}

	res := "-> total bytes of audit record data written to disk: " + humanize.Bytes(uint64(c.totalBytesWritten)) + "\n"

	if c.unkownPcapWriterAtomic != nil {
		if c.unkownPcapWriterAtomic.count > 0 {
			res += "-> " + share(c.unkownPcapWriterAtomic.count, c.numPackets) + " of packets (" + strconv.FormatInt(c.unkownPcapWriterAtomic.count, 10) + ") written to unknown.pcap\n"
		}
	}

	if c.errorsPcapWriterAtomic != nil {
		if c.errorsPcapWriterAtomic.count > 0 {
			res += "-> " + share(c.errorsPcapWriterAtomic.count, c.numPackets) + " of packets (" + strconv.FormatInt(c.errorsPcapWriterAtomic.count, 10) + ") written to errors.pcap\n"
		}
	}

	if _, err := fmt.Fprintln(target, res); err != nil {
		fmt.Println("failed to print stats:", err)
	}

	if c.config.DecoderConfig.SaveConns {
		_, _ = fmt.Fprintln(target, "saved TCP connections:", tcp.NumSavedTCPConns())
		_, _ = fmt.Fprintln(target, "saved UDP conversations:", udp.NumSavedUDPConns())
	}

	// dump label manager stats table if configured
	manager.Stats(target)

	// print tree view of encountered audit records
	c.printTreeView(target)
}

// printTreeView prints a hierarchical tree view of all encountered audit record types
// organized by their correct encapsulation level (Link -> Network -> Transport -> Application)
func (c *Collector) printTreeView(target io.Writer) {
	if c.config.DecoderConfig.Quiet {
		return
	}

	fmt.Fprintln(target, "\n========================================")
	fmt.Fprintln(target, "Encountered Audit Records (Tree View)")
	fmt.Fprintln(target, "========================================")

	// Organize encountered decoders by layer
	decodersByLayer := make(map[string][]string)

	// Collect GoPacket decoders with count > 0
	c.unknownProtosAtomic.Lock()
	for k, v := range c.allProtosAtomic.Items {
		if v > 0 && k != "Payload" {
			layer := determineLayerForDecoder(k)
			decodersByLayer[layer] = append(decodersByLayer[layer], k)
		}
	}
	c.unknownProtosAtomic.Unlock()

	// Collect PacketDecoders with count > 0
	for _, d := range c.packetDecoders {
		if d.NumRecords() > 0 {
			name := d.GetName()
			layer := determineLayerForDecoder(name)
			decodersByLayer[layer] = append(decodersByLayer[layer], name)
		}
	}

	// Collect StreamDecoders with count > 0
	for _, d := range c.streamDecoders {
		if d.NumRecords() > 0 {
			decodersByLayer["Stream Decoders"] = append(decodersByLayer["Stream Decoders"], d.GetName())
		}
	}

	// Collect AbstractDecoders with count > 0
	for _, d := range c.abstractDecoders {
		if d.NumRecords() > 0 {
			decodersByLayer["Abstract Decoders"] = append(decodersByLayer["Abstract Decoders"], d.GetName())
		}
	}

	// Print hierarchical tree
	printEncapsulationTree(target, decodersByLayer)

	fmt.Fprintln(target)
}

// determineLayerForDecoder determines the OSI layer for a decoder based on its name
func determineLayerForDecoder(name string) string {
	nameLower := strings.ToLower(name)

	// Link Layer protocols
	linkLayerProtocols := []string{"ethernet", "arp", "dot1q", "dot11", "llc", "snap",
		"linklayerdiscovery", "ethernetctp", "fddi", "usb", "cisco", "nortel", "vlan"}
	for _, proto := range linkLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Link Layer"
		}
	}

	// Network Layer protocols
	networkLayerProtocols := []string{"ipv4", "ipv6", "icmp", "ipsec", "igmp", "mpls", "gre"}
	for _, proto := range networkLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Network Layer"
		}
	}

	// Transport Layer protocols
	transportLayerProtocols := []string{"tcp", "udp", "sctp"}
	for _, proto := range transportLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Transport Layer"
		}
	}

	// Application Layer protocols
	applicationLayerProtocols := []string{"dns", "dhcp", "http", "tls", "ntp", "sip",
		"smtp", "pop3", "ssh", "lcm", "modbus", "ospf", "bfd", "eap", "cip", "enip",
		"geneve", "vxlan", "vrrp", "diameter", "connection", "deviceprofile", "ipprofile"}
	for _, proto := range applicationLayerProtocols {
		if strings.Contains(nameLower, proto) {
			return "Application Layer"
		}
	}

	return "Application Layer"
}

// printEncapsulationTree prints layers in a hierarchical tree structure
// matching the exact layout from net util -decoders
func printEncapsulationTree(target io.Writer, decodersByLayer map[string][]string) {
	// Print Link Layer at root
	fmt.Fprintln(target, "├── Link Layer")
	if decoders, ok := decodersByLayer["Link Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│   ", false, true) // hasChildLayer=true because Network Layer follows
	}

	// Print Network Layer as child of Link Layer
	fmt.Fprintln(target, "│   └── Network Layer")
	if decoders, ok := decodersByLayer["Network Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│       ", false, true) // hasChildLayer=true because Transport Layer follows
	}

	// Print Transport Layer as child of Network Layer
	fmt.Fprintln(target, "│       └── Transport Layer")
	if decoders, ok := decodersByLayer["Transport Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│           ", false, true) // hasChildLayer=true because Application Layer follows
	}

	// Print Application Layer as child of Transport Layer
	fmt.Fprintln(target, "│           └── Application Layer")
	if decoders, ok := decodersByLayer["Application Layer"]; ok && len(decoders) > 0 {
		printDecoderList(target, decoders, "│               ", true, false) // hasChildLayer=false, this is the end
	}

	// Print Stream Decoders at root level (if any exist)
	if decoders, ok := decodersByLayer["Stream Decoders"]; ok && len(decoders) > 0 {
		fmt.Fprintln(target, "│")
		fmt.Fprintln(target, "├── Stream Decoders")
		printDecoderList(target, decoders, "│   ", false, false) // hasChildLayer=false
	}

	// Print Abstract Decoders at root level (last one, if any exist)
	if decoders, ok := decodersByLayer["Abstract Decoders"]; ok && len(decoders) > 0 {
		fmt.Fprintln(target, "│")
		fmt.Fprintln(target, "└── Abstract Decoders")
		printDecoderList(target, decoders, "    ", true, false) // hasChildLayer=false
	}
}

// printDecoderList prints a list of decoders with the given indent
// hasChildLayer indicates if a child layer follows the decoder list
func printDecoderList(target io.Writer, decoders []string, indent string, isLast bool, hasChildLayer bool) {
	for i, decoder := range decoders {
		isLastDecoder := i == len(decoders)-1
		prefix := indent + "├──"
		// Only use └── if it's the last decoder AND there's no child layer following
		if isLastDecoder && !hasChildLayer {
			prefix = indent + "└──"
		}

		fmt.Fprintf(target, "%s %s\n", prefix, decoder)
	}
}

// updates the progress indicator and writes to stdout.
//func (c *Collector) printProgress() {
//	// increment atomic packet counter
//	atomic.AddInt64(&c.current, 1)
//
//	// must be locked, otherwise a race occurs when sending a SIGINT
//	//  and triggering wg.Wait() in another goroutine...
//	c.statMutex.Lock()
//
//	// increment wait group for packet processing
//	c.wg.Add(1)
//
//	// dont print message when collector is about to shutdown
//	if c.shutdown {
//		c.statMutex.Unlock()
//
//		return
//	}
//	c.statMutex.Unlock()
//
//	if c.current%1000 == 0 {
//		if !c.config.DecoderConfig.Quiet {
//			// using a strings.Builder for assembling string for performance
//			// TODO: could be refactored to use a byte slice with a fixed length instead
//			// TODO: add Builder to collector and flush it every cycle to reduce allocations
//			// also only print flows and collections when the corresponding decoders are active
//			var b strings.Builder
//
//			b.Grow(65)
//			b.WriteString("decoding packets... (")
//			b.WriteString(utils.Progress(c.current, c.numPackets))
//			b.WriteString(")")
//			// b.WriteString(strconv.Itoa(decoder.Flows.Size()))
//			// b.WriteString(" connections: ")
//			// b.WriteString(strconv.Itoa(decoder.Connections.Size()))
//			b.WriteString(" profiles: ")
//			b.WriteString(strconv.Itoa(decoder.DeviceProfiles.Size()))
//			b.WriteString(" packets: ")
//			b.WriteString(strconv.Itoa(int(c.current)))
//
//			// print
//			clearLine()
//
//			_, _ = os.Stdout.WriteString(b.String())
//		}
//	}
//}

// updates the progress indicator and writes to stdout periodically.
func (c *Collector) printProgressInterval() chan struct{} {
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(c.statsInterval):
				// must be locked, otherwise a race occurs when sending a SIGINT
				// and triggering wg.Wait() in another goroutine...
				c.statMutex.Lock()

				// dont print message when collector is about to shutdown
				if c.shutdown {
					c.statMutex.Unlock()
					return
				}
				c.statMutex.Unlock()

				var (
					curr = atomic.LoadInt64(&c.current)
					num  = atomic.LoadInt64(&c.numPackets)
					last = atomic.LoadInt64(&c.numPacketsLast)
					pps  = (curr - last) / int64(c.statsInterval.Seconds())
				)

				// update prometheus metric
				newPacketsPerSecond.WithLabelValues().Set(float64(pps))

				// track value for charting
				c.pps[time.Now()] = float64(pps)

				// update internal stats
				atomic.StoreInt64(&c.numPacketsLast, curr)

				// print to stderr
				if !c.config.DecoderConfig.Quiet || c.config.DecoderConfig.PrintProgress { // print
					c.clearLine()
					_, _ = fmt.Fprintf(os.Stderr,
						c.progressString,
						utils.Progress(curr, num),
						// decoder.Flows.Size(), // TODO: fetch this info from stats?
						// decoder.Connections.Size(), // TODO: fetch this info from stats?
						packet.DeviceProfiles.Size(),
						service.Store.Size(),
						int(curr),
						pps,
					)
					c.log.Sugar().Infof(c.progressString,
						utils.Progress(curr, num),
						// decoder.Flows.Size(), // TODO: fetch this info from stats?
						// decoder.Connections.Size(), // TODO: fetch this info from stats?
						packet.DeviceProfiles.Size(),
						service.Store.Size(),
						int(curr),
						pps)
				}
			}
		}
	}()

	return stop
}

// assemble the progress string once, to reduce recurring allocations.
func (c *Collector) buildProgressString() {
	c.progressString = "decoding packets... (%s) profiles: %d services: %d total packets: %d pkts/sec %d"
}

// GetNumPackets returns the current number of processed packets.
func (c *Collector) GetNumPackets() int64 {
	return atomic.LoadInt64(&c.current)
}

// FreeOSMemory forces freeing memory.
func (c *Collector) freeOSMemory() {
	for range time.After(time.Duration(c.config.FreeOSMem) * time.Minute) {
		debug.FreeOSMemory()
	}
}

// ResetHeaderPrinted resets the flag that tracks whether the netcap header has been printed.
// This is useful when starting a new batch of processing or in testing scenarios.
func ResetHeaderPrinted() {
	headerPrintedLock.Lock()
	headerPrinted = false
	headerPrintedLock.Unlock()
}

// PrintConfiguration dumps the current collector config to stdout.
func (c *Collector) PrintConfiguration() {
	// ensure the logfile handle gets opened
	err := c.initLogging()
	if err != nil {
		log.Fatal("failed to open logfile:", err)
	}

	var target io.Writer
	if c.config.DecoderConfig.Quiet {
		target = c.netcapLogFile
	} else {
		target = io.MultiWriter(os.Stdout, c.netcapLogFile)
	}

	cdata, err := json.MarshalIndent(c.config, " ", "  ")
	if err != nil {
		log.Fatal(err)
	}
	// always write the entire configuration into the logfile
	_, _ = c.netcapLogFile.Write(cdata)

	// Print header only once when processing multiple files
	headerPrintedLock.Lock()
	shouldPrintHeader := !headerPrinted
	if !headerPrinted {
		headerPrinted = true
	}
	headerPrintedLock.Unlock()

	if shouldPrintHeader {
		netio.FPrintLogo(target)
	}

	if c.config.DecoderConfig.Debug && !c.config.DecoderConfig.Quiet {
		// in debug mode and when not silencing stdout via quiet mode: dump config to stdout
		target = io.MultiWriter(os.Stdout, c.netcapLogFile)
	} else {
		// default: write configuration into netcap.log
		target = c.netcapLogFile
		if !c.config.DecoderConfig.Quiet && shouldPrintHeader {
			fmt.Println() // add newline
		}
	}

	if shouldPrintHeader {
		netio.FPrintBuildInfo(target)
	}

	// print build information
	_, _ = fmt.Fprintln(target, "> PID:", os.Getpid())

	// print configuration as table
	tui.Table(target, []string{"Setting", "Value"}, [][]string{
		{"Workers", strconv.Itoa(c.config.Workers)},
		{"MemBuffer", strconv.FormatBool(c.config.DecoderConfig.Buffer)},
		{"MemBufferSize", strconv.Itoa(c.config.DecoderConfig.MemBufferSize) + " bytes"},
		{"Compression", strconv.FormatBool(c.config.DecoderConfig.Compression)},
		{"PacketBuffer", strconv.Itoa(c.config.PacketBufferSize) + " packets"},
		{"PacketContext", strconv.FormatBool(c.config.DecoderConfig.AddContext)},
		{"Payloads", strconv.FormatBool(c.config.DecoderConfig.IncludePayloads)},
		{"FileStorage", c.config.DecoderConfig.FileStorage},
	})

	_, _ = fmt.Fprintln(target) // add a newline
}

// Stop will halt packet collection and wait for all processing to finish.
func (c *Collector) Stop() {
	c.cleanup(false)
}

// forceStop will halt packet collection immediately without waiting for processing to finish.
func (c *Collector) forceStop() {
	c.cleanup(true)
}
