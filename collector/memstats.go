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
