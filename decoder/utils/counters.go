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
	Items map[string]int64
}

// NewAtomicCounterMap returns a new AtomicCounterMap.
func NewAtomicCounterMap() *AtomicCounterMap {
	return &AtomicCounterMap{
		Items: map[string]int64{},
	}
}

// Inc increments a value.
func (a *AtomicCounterMap) Inc(val string) {
	a.Lock()
	a.Items[val]++
	a.Unlock()
}
