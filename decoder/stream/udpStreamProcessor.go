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

package stream

import (
	"bytes"
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/utils"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	udpStreamDecodeTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_udp_stream_decode_time",
			Help: "Time taken to process a UDP stream",
		},
		[]string{"Decoder"},
	)
	udpStreamProcessingTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_udp_stream_processing_time",
			Help: "Time taken to save the UDP stream data to disk",
		},
		[]string{"Direction"},
	)
)

func init() {
	prometheus.MustRegister(
		udpStreamProcessingTime,
		udpStreamDecodeTime,
	)
}

func flushUDPStreams(numTotal int) {

	sp := new(udpStreamProcessor)
	sp.initWorkers(conf.StreamBufferSize)
	sp.numTotal = numTotal

	udpStreams.Lock()

	// flush the remaining streams to disk
	for _, s := range udpStreams.streams {
		if s != nil { // never feed a nil stream
			sp.handleStream(s)
		}
	}

	udpStreams.Unlock()

	streamLog.Info("waiting for stream processor wait group... ")
	sp.wg.Wait()

	// explicitly feed a nil stream to exit the goroutines used for processing
	for _, w := range sp.workers {
		w <- nil
	}
}

// internal data structure to parallelize processing of tcp streams
// when the core engine is stopped and the remaining open connections are processed.
type udpStreamProcessor struct {
	workers          []chan *udpStream
	numWorkers       int
	next             int
	wg               sync.WaitGroup
	numDone          int
	numTotal         int
	streamBufferSize int
	sync.Mutex
}

// to process the streams in parallel
// they are passed to several worker goroutines in round robin style.
func (usp *udpStreamProcessor) handleStream(s *udpStream) {
	usp.wg.Add(1)

	// make it work for 1 worker only, can be used for debugging
	//if c.numWorkers == 1 {
	//	c.workers[0] <- s
	//	return
	//}

	// send the packetInfo to the decoder routine
	usp.workers[usp.next] <- s

	// increment or reset next
	if usp.numWorkers == usp.next+1 {
		// reset
		usp.next = 0
	} else {
		usp.next++
	}
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
// the wait group has already been incremented for each non-nil packet,
// so wg.Done() must be called before returning for each item.
func (usp *udpStreamProcessor) streamWorker(wg *sync.WaitGroup) chan *udpStream {
	// init channel to receive input packets
	chanInput := make(chan *udpStream, usp.streamBufferSize)

	// start worker
	go func() {
		for s := range chanInput {
			// nil packet is used to exit the loop,
			// the processing logic will never send a streamReader in here that is nil
			if s == nil {
				return
			}

			s.Lock()
			sort.Sort(s.data)

			var (
				clientNetwork            gopacket.Flow
				clientTransport          gopacket.Flow
				firstPacket              time.Time
				ident                    string
				serverBytes, clientBytes int
			)

			// check who is client and who server based on first packet
			if len(s.data) > 0 {
				clientTransport = s.data[0].transport()
				clientNetwork = s.data[0].network()
				firstPacket = s.data[0].captureInfo().Timestamp
				ident = utils.CreateFlowIdentFromLayerFlows(clientNetwork, clientTransport)
			} else {
				// skip empty conns
				continue
			}

			var serverBanner bytes.Buffer

			for _, d := range s.data {
				if d.transport() == clientTransport {
					clientBytes += len(d.raw())
				} else {
					// server
					serverBytes += len(d.raw())
					for _, b := range d.raw() {
						if serverBanner.Len() == conf.BannerSize {
							break
						}
						serverBanner.WriteByte(b)
					}
				}
			}
			s.Unlock()

			// call stream decoders
			s.decode()

			// save stream data
			err := saveConversation(protoUDP, s.data, ident, firstPacket, clientTransport)
			if err != nil {
				fmt.Println("failed to save UDP conversation:", err)
			}

			// save service banner
			saveUDPServiceBanner(
				serverBanner.Bytes(),
				ident,
				clientNetwork.Dst().String()+":"+clientTransport.Dst().String(),
				firstPacket,
				serverBytes,
				clientBytes,
				clientNetwork,
				clientTransport,
			)

			usp.Lock()
			usp.numDone++

			if !conf.Quiet {
				utils.ClearLine()
				fmt.Print("processing UDP streams... ", "(", usp.numDone, "/", usp.numTotal, ")")
			}

			usp.Unlock()
			wg.Done()
		}
	}()

	// return input channel
	return chanInput
}

// spawn the configured number of workers.
func (usp *udpStreamProcessor) initWorkers(streamBufferSize int) {
	usp.streamBufferSize = streamBufferSize

	// TODO: make configurable
	usp.workers = make([]chan *udpStream, 1000)

	for i := range usp.workers {
		usp.workers[i] = usp.streamWorker(&usp.wg)
	}

	usp.numWorkers = len(usp.workers)
}
