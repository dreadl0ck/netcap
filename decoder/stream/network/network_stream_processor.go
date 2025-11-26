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

package network

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/prometheus/client_golang/prometheus"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	networkStreamProcessingTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_network_stream_processing_time",
			Help: "Time taken to process a network-layer stream",
		},
		[]string{"Protocol"},
	)
)

func init() {
	prometheus.MustRegister(networkStreamProcessingTime)
}

// FlushNetworkStreams will flush all collected network-layer streams to disk
func FlushNetworkStreams() {
	numTotal := Streams.size()
	if numTotal == 0 {
		return
	}

	sp := new(networkStreamProcessor)
	if numTotal < decoderconfig.Instance.NumStreamWorkers {
		sp.initWorkers(decoderconfig.Instance.StreamBufferSize, numTotal)
	} else {
		sp.initWorkers(decoderconfig.Instance.StreamBufferSize, decoderconfig.Instance.NumStreamWorkers)
	}
	sp.numTotal = numTotal

	Streams.Lock()

	// Flush the remaining streams to disk
	for _, s := range Streams.streams {
		if s != nil {
			sp.handleStream(s)
		}
	}

	Streams.Unlock()

	sp.wg.Wait()

	// Explicitly send nil to exit the goroutines
	for i, w := range sp.workers {
		w <- nil
		close(w)
		sp.workers[i] = nil
	}
}

// networkStreamProcessor handles parallel processing of network streams
type networkStreamProcessor struct {
	sync.Mutex
	workers          []chan *networkStream
	numWorkers       int
	next             int
	wg               sync.WaitGroup
	numDone          int
	numTotal         int
	streamBufferSize int
}

// handleStream passes a stream to a worker for processing
func (nsp *networkStreamProcessor) handleStream(s *networkStream) {
	nsp.wg.Add(1)
	nsp.workers[nsp.next] <- s

	// Round robin to next worker
	if nsp.numWorkers == nsp.next+1 {
		nsp.next = 0
	} else {
		nsp.next++
	}
}

// streamWorker spawns a new worker goroutine
func (nsp *networkStreamProcessor) streamWorker(wg *sync.WaitGroup) chan *networkStream {
	chanInput := make(chan *networkStream, nsp.streamBufferSize)

	go func() {
		for s := range chanInput {
			if s == nil {
				return
			}

			ti := time.Now()

			s.Lock()
			s.data.Sort()

			var (
				clientNetwork gopacket.Flow
				firstPacket   time.Time
				ident         string
			)

			// Check who is client based on first packet
			if len(s.data) > 0 {
				clientNetwork = s.data[0].Network()
				firstPacket = s.data[0].CaptureInfo().Timestamp
				ident = createNetworkFlowIdent(clientNetwork)
			} else {
				s.Unlock()
				wg.Done()
				continue
			}

			// Set directions for all fragments based on first packet
			for _, d := range s.data {
				if d.Network() == clientNetwork {
					d.SetDirection(reassembly.TCPDirClientToServer)
				} else {
					d.SetDirection(reassembly.TCPDirServerToClient)
				}
			}

			protocol := s.protocol
			
			// Convert to interface slice for SaveNetworkConversation
			fragments := make(streamutils.NetworkDataFragments, len(s.data))
			for i, d := range s.data {
				fragments[i] = d
			}
			s.Unlock()

			// Save stream data
			err := streamutils.SaveNetworkConversation(protocol, fragments, ident, firstPacket)
			if err != nil {
				fmt.Println("failed to save network conversation:", err)
			}

			networkStreamProcessingTime.WithLabelValues(protocol).Set(float64(time.Since(ti).Nanoseconds()))

			nsp.Lock()
			nsp.numDone++

			if !decoderconfig.Instance.Quiet && nsp.numTotal > 0 {
				utils.ClearLine()
				fmt.Print("processing network streams... ", "(", nsp.numDone, "/", nsp.numTotal, ")")
			}

			nsp.Unlock()
			wg.Done()
		}
	}()

	return chanInput
}

// initWorkers spawns the configured number of workers
func (nsp *networkStreamProcessor) initWorkers(streamBufferSize int, numStreamWorkers int) {
	nsp.streamBufferSize = streamBufferSize
	nsp.workers = make([]chan *networkStream, numStreamWorkers)

	for i := range nsp.workers {
		nsp.workers[i] = nsp.streamWorker(&nsp.wg)
	}

	nsp.numWorkers = len(nsp.workers)
}

// createNetworkFlowIdent creates a flow identifier from network layer only
func createNetworkFlowIdent(network gopacket.Flow) string {
	srcIP := ""
	dstIP := ""

	if len(network.Src().Raw()) > 0 {
		srcIP = network.Src().String()
	}
	if len(network.Dst().Raw()) > 0 {
		dstIP = network.Dst().String()
	}

	return utils.CreateFlowIdent(srcIP, "", dstIP, "")
}

// NumSavedNetworkConns returns the number of saved network-layer conversations
func NumSavedNetworkConns() int64 {
	streamutils.Stats.Lock()
	defer streamutils.Stats.Unlock()
	return streamutils.Stats.SavedNetworkConnections
}

