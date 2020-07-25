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
package decoder

import (
	"fmt"

	"runtime"
	"sync"
)

// internal data structure to parallelize processing of tcp streams
// when the core engine is stopped and the remaining open connections are processed
type tcpStreamProcessor struct {
	workers    []chan StreamReader
	numWorkers int
	next       int
	wg         sync.WaitGroup
	numDone    int
	numTotal   int
	sync.Mutex
}

// to process the streams in parallel
// they are passed to several worker goroutines in round robin style.
func (tsp *tcpStreamProcessor) handleStream(s StreamReader) {

	tsp.wg.Add(1)

	// make it work for 1 worker only, can be used for debugging
	//if c.numWorkers == 1 {
	//	c.workers[0] <- s
	//	return
	//}

	// send the packetInfo to the encoder routine
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
func (tsp *tcpStreamProcessor) streamWorker(wg *sync.WaitGroup) chan StreamReader {

	// init channel to receive input packets
	chanInput := make(chan StreamReader, 10)

	// start worker
	go func() {
		for {
			select {
			case s := <-chanInput:
				if s == nil {
					return
				}

				// do not process streams that have been saved already by their cleanup functions
				// because the corresponding connection has been closed
				if s.Saved() {
					break
				}

				if s.IsClient() {
					// save the entire conversation.
					// we only need to do this once, when the client part of the connection is closed
					err := saveConnection(s.ConversationRaw(), s.ConversationColored(), s.Ident(), s.FirstPacket(), s.Transport())
					if err != nil {
						fmt.Println("failed to save connection", err)
					}
				} else {
					s.SortAndMergeFragments()

					// save the service banner
					saveTCPServiceBanner(s)
				}
			}

			tsp.Lock()
			tsp.numDone++

			if !Quiet {
				clearLine()
				fmt.Print("processing remaining open TCP streams... ", "(", tsp.numDone, "/", tsp.numTotal, ")")
			}
			tsp.Unlock()

			wg.Done()
			continue
		}
	}()

	// return input channel
	return chanInput
}

// spawn the configured number of workers
func (tsp *tcpStreamProcessor) initWorkers() {
	tsp.workers = make([]chan StreamReader, runtime.NumCPU())
	for i := range tsp.workers {
		tsp.workers[i] = tsp.streamWorker(&tsp.wg)
	}
	tsp.numWorkers = len(tsp.workers)
}
