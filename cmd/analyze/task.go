/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

// cleanupWorkers closes all worker channels to signal goroutines to exit
// This prevents goroutine leaks in multi-file processing mode
func cleanupWorkers() {
	for i, w := range workers {
		if w != nil {
			close(w)
			workers[i] = nil
		}
	}
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func worker() chan task {

	// init channel to receive paths
	chanInput := make(chan task, 1)

	// start worker
	go func() {
		// Range over channel automatically handles channel closure
		for t := range chanInput {
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
		}
	}()

	// return input channel
	return chanInput
}
