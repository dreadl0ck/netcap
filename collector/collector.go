/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package collector

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/utils"
	humanize "github.com/dustin/go-humanize"
	"github.com/evilsocket/islazy/tui"
	"github.com/google/gopacket"
	"github.com/mgutz/ansi"
)

// Collector provides an interface to collect data from PCAP or a network interface.
type Collector struct {

	// input channels for the worker pool
	workers []chan gopacket.Packet

	// synchronization
	statMutex sync.Mutex
	wg        sync.WaitGroup
	next      int
	current   int64

	// unknown protocol pcap writer
	unkownPcapWriterBuffered *bufio.Writer
	unkownPcapWriterAtomic   *AtomicPcapGoWriter
	unknownPcapFile          *os.File

	// error pcap writer
	errorsPcapWriterBuffered *bufio.Writer
	errorsPcapWriterAtomic   *AtomicPcapGoWriter
	errorsPcapFile           *os.File

	// error log file handle
	errorLogFile *os.File

	// protocol maps
	unknownProtosAtomic *encoder.AtomicCounterMap
	allProtosAtomic     *encoder.AtomicCounterMap

	// processing errors
	errorMap *encoder.AtomicCounterMap

	// stats
	start             time.Time
	numPackets        int64
	totalBytesWritten int64
	files             map[string]string
	inputSize         int64

	// configuration
	config *Config
}

// New returns a new Collector instance.
func New(config Config) *Collector {
	return &Collector{
		next:                1,
		unknownProtosAtomic: encoder.NewAtomicCounterMap(),
		allProtosAtomic:     encoder.NewAtomicCounterMap(),
		errorMap:            encoder.NewAtomicCounterMap(),
		files:               map[string]string{},
		config:              &config,
		start:               time.Now(),
	}
}

// stopWorkers halts all workers.
func (c *Collector) stopWorkers() {
	// wait until all packets have been decoded
	for _, w := range c.workers {
		w <- nil
		// TODO closing here produces a data race
		// close(w)
	}
}

// cleanup before leaving. closes all buffers and displays stats.
func (c *Collector) cleanup() {

	c.statMutex.Lock()
	c.wg.Wait()
	c.statMutex.Unlock()

	if c.config.Live {
		c.statMutex.Lock()
		c.numPackets = c.current
		c.statMutex.Unlock()
	}

	clearLine()
	println("done.\n")
	c.stopWorkers()

	// sync pcap file
	c.closePcapFiles()

	// flush all buffers
	for _, encoders := range encoder.LayerEncoders {
		for _, e := range encoders {
			name, size := e.Destroy()
			if size != 0 {
				c.totalBytesWritten += size
				c.files[name] = humanize.Bytes(uint64(size))
			}
		}
	}

	// flush all buffers
	for _, e := range encoder.CustomEncoders {
		name, size := e.Destroy()
		if size != 0 {
			c.totalBytesWritten += size
			c.files[name] = humanize.Bytes(uint64(size))
		}
	}

	c.closeErrorLogFile()
	c.Stats()

	// encoder.DumpTop5LinkFlows()
	// encoder.DumpTop5NetworkFlows()
	// encoder.DumpTop5TransportFlows()

	c.printErrors()
}

// handleSignals catches signals and runs the cleanup
// SIGQUIT is not catched, to allow debugging by producing a stack and goroutine trace.
func (c *Collector) handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// start signal handler and cleanup routine
	go func() {
		_ = <-sigs

		c.cleanup()
		os.Exit(0)
	}()
}

// to decode incoming packets in parallel
// they are passed to several worker goroutines in round robin style.
func (c *Collector) handlePacket(p gopacket.Packet) {

	// make it work for 1 worker only
	// if len(c.workers) == 1 {
	// 	c.workers[0] <- p
	// 	return
	// }

	// send the packetInfo to the encoder routine
	c.workers[c.next] <- p

	// increment or reset next
	if c.config.NumWorkers >= c.next+1 {
		// reset
		c.next = 1
	} else {
		c.next++
	}
}

// print errors to stdout in red.
func (c *Collector) printErrors() {
	c.errorMap.Lock()
	if len(c.errorMap.Items) > 0 {
		fmt.Println("")
		for msg, count := range c.errorMap.Items {
			fmt.Println(ansi.Red, "[ERROR]", msg, "COUNT:", count, ansi.Reset)
		}
		fmt.Println("")
	}
	c.errorMap.Unlock()
}

// closes the logfile for errors.
func (c *Collector) closeErrorLogFile() {

	// append  stats
	var stats string
	for msg, count := range c.errorMap.Items {
		stats += fmt.Sprintln("[ERROR]", msg, "COUNT:", count)
	}

	_, err := c.errorLogFile.WriteString(stats)
	if err != nil {
		panic(err)
	}

	// sync
	err = c.errorLogFile.Sync()
	if err != nil {
		panic(err)
	}

	// close file handle
	err = c.errorLogFile.Close()
	if err != nil {
		panic(err)
	}
}

// Stats prints collector statistics.
func (c *Collector) Stats() {

	rows := [][]string{}

	for k, v := range c.allProtosAtomic.Items {
		if _, ok := c.unknownProtosAtomic.Items[k]; ok {
			rows = append(rows, []string{ansi.Yellow + k, fmt.Sprint(v), share(v, c.numPackets) + ansi.Reset})
		} else {
			rows = append(rows, []string{k, fmt.Sprint(v), share(v, c.numPackets)})
		}
	}
	tui.Table(os.Stdout, []string{"Layer", "NumPackets", "Share"}, rows)

	if len(encoder.CustomEncoders) > 0 {
		rows = [][]string{}
		for _, e := range encoder.CustomEncoders {
			rows = append(rows, []string{e.Name, strconv.FormatInt(e.NumRecords(), 10), share(e.NumRecords(), c.numPackets)})
		}
		tui.Table(os.Stdout, []string{"CustomEncoder", "NumRecords", "Share"}, rows)
	}

	res := "\n-> total bytes of data written to disk: " + humanize.Bytes(uint64(c.totalBytesWritten)) + "\n"
	if c.unkownPcapWriterAtomic.count > 0 {
		res += "-> " + share(c.unkownPcapWriterAtomic.count, c.numPackets) + " of packets (" + strconv.FormatInt(c.unkownPcapWriterAtomic.count, 10) + ") written to unknown.pcap\n"
	}

	if c.errorsPcapWriterAtomic.count > 0 {
		res += "-> " + share(c.errorsPcapWriterAtomic.count, c.numPackets) + " of packets (" + strconv.FormatInt(c.errorsPcapWriterAtomic.count, 10) + ") written to errors.pcap\n"
	}
	fmt.Println(res)
}

// updates the progress indicator and writes to stdout.
func (c *Collector) printProgress() {

	// must be locked, otherwise a race occurs when sending a SIGINT
	//  and triggering wg.Wait() in another goroutine...
	c.statMutex.Lock()
	c.wg.Add(1)
	c.statMutex.Unlock()
	atomic.AddInt64(&c.current, 1)

	if c.current%10000 == 0 {

		// using a strings.Builder for assembling string for performance
		// TODO: could be refactored to use a byte slice with a fixed length instead
		// also only print flows and collections when the corresponding encoders are active
		var b strings.Builder
		b.Grow(65)
		b.WriteString("decoding packets... (")
		b.WriteString(utils.Progress(c.current, c.numPackets))
		b.WriteString(") flows: ")
		b.WriteString(strconv.Itoa(encoder.Flows.Size()))
		b.WriteString(" connections: ")
		b.WriteString(strconv.Itoa(encoder.Connections.Size()))

		// print
		clearLine()
		os.Stdout.WriteString(b.String())
	}
}

// Init sets up the collector and starts the configured number of workers
// must be called prior to usage of the collector instance.
func (c *Collector) Init() (err error) {

	// start workers
	c.workers = c.initWorkers()
	fmt.Println("spawned", c.config.Workers, "workers")

	// set number of workers
	c.config.NumWorkers = len(c.workers)

	// create full output directory path if set
	if c.config.EncoderConfig.Out != "" {
		err = os.MkdirAll(c.config.EncoderConfig.Out, 0755)
		if err != nil {
			return err
		}
	}

	// initialize encoders
	encoder.InitLayerEncoders(c.config.EncoderConfig)
	encoder.InitCustomEncoders(c.config.EncoderConfig)

	// set payload capture
	encoder.CapturePayload = c.config.EncoderConfig.IncludePayloads

	// set pointer of collectors atomic counter map in encoder pkg
	encoder.SetErrorMap(c.errorMap)

	// create pcap files for packets
	// with unknown protocols or errors while decoding
	c.createUnknownPcap()
	c.createErrorsPcap()

	// handle signal for a clean exit
	c.handleSignals()

	// create log file
	c.errorLogFile, err = os.Create(filepath.Join(c.config.EncoderConfig.Out, "errors.log"))

	return
}
