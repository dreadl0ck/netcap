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

package udp

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/prometheus/client_golang/prometheus"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/utils"
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

// FlushUDPStreams will flush all collected UDP streams to disk.
func FlushUDPStreams() {
	numTotal := Streams.size()

	sp := new(udpStreamProcessor)
	if numTotal < decoderconfig.Instance.NumStreamWorkers {
		sp.initWorkers(decoderconfig.Instance.StreamBufferSize, numTotal)
	} else {
		sp.initWorkers(decoderconfig.Instance.StreamBufferSize, decoderconfig.Instance.NumStreamWorkers)
	}
	sp.numTotal = numTotal

	Streams.Lock()

	// flush the remaining streams to disk
	for _, s := range Streams.streams {
		if s != nil { // never feed a nil stream
			sp.handleStream(s)
		}
	}

	Streams.Unlock()

	// reassemblyLog.Info("waiting for stream processor wait group... ")
	sp.wg.Wait()

	// explicitly feed a nil stream to exit the goroutines used for processing
	for i, w := range sp.workers {
		w <- nil            // Signal worker to exit
		close(w)            // Close the channel
		sp.workers[i] = nil // Nil out reference to help GC
	}
}

// internal data structure to parallelize processing of tcp streams
// when the core engine is stopped and the remaining open connections are processed.
type udpStreamProcessor struct {
	sync.Mutex
	workers          []chan *udpStream
	numWorkers       int
	next             int
	wg               sync.WaitGroup
	numDone          int
	numTotal         int
	streamBufferSize int
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
				clientTransport = s.data[0].Transport()
				clientNetwork = s.data[0].Network()
				firstPacket = s.data[0].CaptureInfo().Timestamp
				ident = utils.CreateFlowIdentFromLayerFlows(clientNetwork, clientTransport)
			} else {
				// skip empty conns
				continue
			}

		var serverBanner bytes.Buffer

		// Track if we've captured the first server packet for banner extraction
		var firstServerPacketCaptured bool

		for _, d := range s.data {
			if d.Transport() == clientTransport {
				clientBytes += len(d.Raw())
			} else {
				// server
				serverBytes += len(d.Raw())
				
				// Extract banner ONLY from the first server packet
				// Nmap service probes are designed to match against the initial server greeting
				if !firstServerPacketCaptured {
					limit := len(d.Raw())
					if limit > decoderconfig.Instance.BannerSize {
						limit = decoderconfig.Instance.BannerSize
					}
					serverBanner.Write(d.Raw()[:limit])
					firstServerPacketCaptured = true
				}
			}
		}
			s.Unlock()

			// call stream decoders
			s.decode()

			// save stream data
			err := streamutils.SaveConversation("UDP", s.data, ident, firstPacket, clientTransport)
			if err != nil {
				fmt.Println("failed to save UDP conversation:", err)
			}

			// save service banner
			// Safely build server address string
			serverAddr := ""
			if len(clientNetwork.Dst().Raw()) > 0 {
				serverAddr = clientNetwork.Dst().String()
			}
			serverAddr += ":"
			if len(clientTransport.Dst().Raw()) > 0 {
				serverAddr += clientTransport.Dst().String()
			}

			saveUDPServiceBanner(
				serverBanner.Bytes(),
				ident,
				serverAddr,
				firstPacket,
				serverBytes,
				clientBytes,
				clientNetwork,
				clientTransport,
			)

			usp.Lock()
			usp.numDone++

			if !decoderconfig.Instance.Quiet && usp.numTotal > 0 {
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
func (usp *udpStreamProcessor) initWorkers(streamBufferSize int, numStreamWorkers int) {
	usp.streamBufferSize = streamBufferSize
	usp.workers = make([]chan *udpStream, numStreamWorkers)

	for i := range usp.workers {
		usp.workers[i] = usp.streamWorker(&usp.wg)
	}

	usp.numWorkers = len(usp.workers)
}
