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

package main

import (
	"fmt"
	"log"
	"sync"
)

// For strings: num variants
// For nums: stddev, mean, min, max
type fileSummary struct {
	file      string
	lineCount int
	columns   []string

	// mapped column names to number of hits for each unique string
	strings       map[string]map[string]int
	skipped       int
	attacks       int
	uniqueAttacks map[string]struct{}
}

func (f *fileSummary) String() string {
	return fmt.Sprintf("lines: %d, columns: %d, strings: %d, skipped: %d, attacks: %d, uniqueAttacks: %d", f.lineCount, len(f.columns), len(f.strings), f.skipped, f.attacks, len(f.uniqueAttacks))
}

type datasetSummary struct {
	fileCount int
	lineCount int
	columns   []string

	// mapped column names to number of hits for each unique string
	strings map[string]map[string]int
}

/*
 * Task
 */

type taskType int

const (
	typeAnalyze = iota
	typeLabel
)

func (c taskType) String() string {
	switch c {
	case typeAnalyze:
		return "typeAnalyze"
	case typeLabel:
		return "typeLabel"
	default:
		return "invalid"
	}
}

type task struct {
	typ                 taskType
	file                string
	current, totalFiles int
	wg                  *sync.WaitGroup
}

func handleTask(t task) {

	// make it work for 1 worker only
	if len(workers) == 1 {
		workers[0] <- t
		return
	}

	// send the packetInfo to the encoder routine
	workers[next] <- t

	// increment or reset next
	if next+1 >= *flagNumWorkers {
		// reset
		next = 1
	} else {
		next++
	}
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func worker() chan task {

	// init channel to receive paths
	chanInput := make(chan task, 1)

	// start worker
	go func() {
		for {
			select {
			case t := <-chanInput:
				switch t.typ {
				case typeAnalyze:
					s := t.analyze()
					resultMutex.Lock()
					results[t.file] = s
					resultMutex.Unlock()
				case typeLabel:
					t.label()
				default:
					log.Fatal("unknown task type: ", t.typ)
				}
				continue
			}
		}
	}()

	// return input channel
	return chanInput
}
