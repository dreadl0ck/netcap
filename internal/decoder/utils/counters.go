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

package utils

import "sync"

// AtomicCounterMap maps strings to integers.
type AtomicCounterMap struct {
	sync.Mutex
	Items  map[string]int64
	shards []*AtomicCounterMap
}

// NewAtomicCounterMap returns a new AtomicCounterMap.
func NewAtomicCounterMap() *AtomicCounterMap {
	return &AtomicCounterMap{
		Items: map[string]int64{},
	}
}

// NewShard registers a worker-local counter on the root. Call only on the root.
func (a *AtomicCounterMap) NewShard() *AtomicCounterMap {
	shard := NewAtomicCounterMap()
	a.Lock()
	a.shards = append(a.shards, shard)
	a.Unlock()
	return shard
}

// Snapshot copies root and shard counts. Each map is read under its own lock;
// the result is not a global cross-shard transaction.
func (a *AtomicCounterMap) Snapshot() map[string]int64 {
	a.Lock()
	defer a.Unlock()

	items := make(map[string]int64, len(a.Items))
	for k, v := range a.Items {
		items[k] = v
	}
	for _, shard := range a.shards {
		shard.Lock()
		for k, v := range shard.Items {
			items[k] += v
		}
		shard.Unlock()
	}
	return items
}

// Inc increments a value.
func (a *AtomicCounterMap) Inc(val string) {
	a.Lock()
	a.Items[val]++
	a.Unlock()
}
