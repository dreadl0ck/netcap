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

package collector

import (
	"encoding/json"
	"runtime"

	"github.com/dustin/go-humanize"
)

// memStats saves selected memory stats from the go runtime in human readable format
type memStats struct {

	// bytes as human readable string
	Alloc      string
	TotalAlloc string
	Sys        string

	Mallocs      int
	Frees        int
	LiveObjects  int
	PauseTotalNs int

	NumGC        uint32
	NumGoroutine int
}

func (m *memStats) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

func newMemStats() *memStats {

	var (
		m   = new(memStats)
		rtm runtime.MemStats
	)

	// read mem stats
	runtime.ReadMemStats(&rtm)

	// collect number of goroutines
	m.NumGoroutine = runtime.NumGoroutine()

	// collect memory stats
	m.Alloc = humanize.Bytes(rtm.Alloc)
	m.TotalAlloc = humanize.Bytes(rtm.TotalAlloc)
	m.Sys = humanize.Bytes(rtm.Sys)

	m.Mallocs = int(rtm.Mallocs)
	m.Frees = int(rtm.Frees)
	m.LiveObjects = m.Mallocs - m.Frees

	// GC stats
	m.PauseTotalNs = int(rtm.PauseTotalNs)
	m.NumGC = rtm.NumGC

	return m
}
