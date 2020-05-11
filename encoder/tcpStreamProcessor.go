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
package encoder

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
func (c *tcpStreamProcessor) handleStream(s StreamReader) {

	c.wg.Add(1)

	// make it work for 1 worker only, can be used for debugging
	if len(c.workers) == 1 {
		c.workers[0] <- s
		return
	}

	// send the packetInfo to the encoder routine
	c.workers[c.next] <- s

	// increment or reset next
	if c.numWorkers == c.next+1 {
		// reset
		c.next = 0
	} else {
		c.next++
	}
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func (c *tcpStreamProcessor) streamWorker(wg *sync.WaitGroup) chan StreamReader {

	// init channel to receive input packets
	chanInput := make(chan StreamReader, 0)

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
					// we only need to do this once, when client part of the connection is closed
					err := saveConnection(s.ConversationRaw(), s.ConversationColored(), s.Ident(), s.FirstPacket(), s.Transport())
					if err != nil {
						fmt.Println("failed to save connection", err)
					}
				} else {
					// save the service banner
					saveTCPServiceBanner(s.ServerStream(), s.Ident(), s.FirstPacket(), s.Network(), s.Transport(), s.NumBytes(), s.Client().NumBytes())
				}
			}

			c.Lock()
			c.numDone++
			if c.numDone%100 == 0 {
				clearLine()
				fmt.Print("processing remaining open TCP streams... ", "(", c.numDone, "/", c.numTotal, ")")
			}
			c.Unlock()

			wg.Done()
			continue
		}
	}()

	// return input channel
	return chanInput
}

// spawn the configured number of workers
func (c *tcpStreamProcessor) initWorkers() {
	c.workers = make([]chan StreamReader, runtime.NumCPU())
	for i := range c.workers {
		c.workers[i] = c.streamWorker(&c.wg)
	}
	c.numWorkers = len(c.workers)
}
