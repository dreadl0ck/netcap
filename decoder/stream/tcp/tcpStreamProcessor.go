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

package tcp

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	tcpStreamDecodeTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_tcp_stream_decode_time",
			Help: "Time taken to process a TCP stream",
		},
		[]string{"Decoder"},
	)
	tcpStreamFeedDataTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_tcp_stream_feed_data_time",
			Help: "Time taken to feed data to a TCP stream consumer",
		},
		[]string{"Direction"},
	)
	tcpStreamProcessingTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_tcp_stream_processing_time",
			Help: "Time taken to save the data to disk",
		},
		[]string{"Direction"},
	)
)

func init() {
	prometheus.MustRegister(
		tcpStreamProcessingTime,
		tcpStreamDecodeTime,
		tcpStreamFeedDataTime,
	)
}

func flushTCPStreams(numTotal int) {
	sp := new(tcpStreamProcessor)
	if numTotal < decoderconfig.Instance.NumStreamWorkers {
		sp.initWorkers(decoderconfig.Instance.StreamBufferSize, numTotal)
	} else {
		sp.initWorkers(decoderconfig.Instance.StreamBufferSize, decoderconfig.Instance.NumStreamWorkers)
	}
	sp.numTotal = numTotal

	// flush the remaining streams to disk
	for _, s := range StreamFactory.streamReaders {
		if s != nil { // never feed a nil stream
			sp.handleStream(s)
		}
	}

	reassemblyLog.Info("waiting for stream processor wait group... ")
	sp.wg.Wait()

	// explicitly feed a nil stream to exit the goroutines used for processing
	for _, w := range sp.workers {
		w <- nil
	}
}

// internal data structure to parallelize processing of tcp streams
// when the core engine is stopped and the remaining open connections are processed.
type tcpStreamProcessor struct {
	sync.Mutex
	workers          []chan streamReader
	numWorkers       int
	next             int
	wg               sync.WaitGroup
	numDone          int
	numTotal         int
	streamBufferSize int
}

// to process the streams in parallel
// they are passed to several worker goroutines in round robin style.
func (tsp *tcpStreamProcessor) handleStream(s streamReader) {
	tsp.wg.Add(1)

	// make it work for 1 worker only, can be used for debugging
	//if c.numWorkers == 1 {
	//	c.workers[0] <- s
	//	return
	//}

	// send the packetInfo to the decoder routine
	tsp.workers[tsp.next] <- s

	// increment or reset next
	if tsp.numWorkers == tsp.next+1 {
		// reset
		tsp.next = 0
	} else {
		tsp.next++
	}
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
// the wait group has already been incremented for each non-nil packet,
// so wg.Done() must be called before returning for each item.
func (tsp *tcpStreamProcessor) streamWorker(wg *sync.WaitGroup) chan streamReader {
	// init channel to receive input packets
	chanInput := make(chan streamReader, tsp.streamBufferSize)

	// start worker
	go func() {
		for s := range chanInput {
			// nil packet is used to exit the loop,
			// the processing logic will never send a streamReader in here that is nil
			if s == nil {
				return
			}

			// do not process streams that have been saved already by their cleanup functions
			// because the corresponding connection has been closed
			if s.Saved() {
				wg.Done()

				continue
			}

			t := time.Now()
			if s.IsClient() {
				// save the entire conversation.
				// we only need to do this once, when the client part of the connection is closed
				err := streamutils.SaveConversation("TCP", s.Merged(), s.Ident(), s.FirstPacket(), s.Transport())
				if err != nil {
					fmt.Println("failed to save connection", err)
				}

				tcpStreamProcessingTime.WithLabelValues(reassembly.TCPDirClientToServer.String()).Set(float64(time.Since(t).Nanoseconds()))

				// decode the actual conversation.
				// this needs to be invoked only once, and since ReassemblyComplete is invoked for each side of the connection
				// DecodeConversation should be called either when processing the client or the server stream
				s.DecodeConversation()
			} else {
				s.SortAndMergeFragments()

				// save the service banner
				saveTCPServiceBanner(s)

				tcpStreamProcessingTime.WithLabelValues(reassembly.TCPDirServerToClient.String()).Set(float64(time.Since(t).Nanoseconds()))
			}

			tsp.Lock()
			tsp.numDone++

			if !decoderconfig.Instance.Quiet {
				utils.ClearLine()
				fmt.Print("processing remaining open TCP streams... ", "(", tsp.numDone, "/", tsp.numTotal, ")")
			}

			tsp.Unlock()
			wg.Done()
		}
	}()

	// return input channel
	return chanInput
}

// spawn the configured number of workers.
func (tsp *tcpStreamProcessor) initWorkers(streamBufferSize int, numStreamWorkers int) {
	tsp.streamBufferSize = streamBufferSize
	tsp.workers = make([]chan streamReader, numStreamWorkers)

	for i := range tsp.workers {
		tsp.workers[i] = tsp.streamWorker(&tsp.wg)
	}

	tsp.numWorkers = len(tsp.workers)
}
