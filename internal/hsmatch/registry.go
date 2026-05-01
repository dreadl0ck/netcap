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

package hsmatch

import (
	"sort"
	"sync"
)

// Subsystem returns a free-form, JSON-friendly snapshot of one Hyperscan
// consumer (service probes, CMS detection, rule engine, …). The exact
// shape is owned by the consumer — the registry just routes it.
type Subsystem interface {
	Name() string
	Snapshot() any
}

// SubsystemFunc adapts a closure into a Subsystem.
type SubsystemFunc struct {
	N string
	F func() any
}

// Name implements [Subsystem].
func (s SubsystemFunc) Name() string { return s.N }

// Snapshot implements [Subsystem].
func (s SubsystemFunc) Snapshot() any { return s.F() }

var (
	registryMu sync.RWMutex
	registry   = map[string]Subsystem{}
)

// RegisterSubsystem adds (or replaces) a subsystem-stats producer keyed by
// name. Safe to call from package init or from runtime build hooks.
//
// Both build configurations expose this function so registration sites
// remain unconditional. In stub builds, registered snapshots still flow
// through Snapshot()/SnapshotMap() — useful for "Enabled: false" surfaces.
func RegisterSubsystem(s Subsystem) {
	if s == nil || s.Name() == "" {
		return
	}
	registryMu.Lock()
	registry[s.Name()] = s
	registryMu.Unlock()
}

// UnregisterSubsystem removes a previously registered producer. Used by
// tests; production code typically registers once at init.
func UnregisterSubsystem(name string) {
	registryMu.Lock()
	delete(registry, name)
	registryMu.Unlock()
}

// NamedSnapshot pairs a subsystem name with its current snapshot.
type NamedSnapshot struct {
	Name string `json:"name"`
	Data any    `json:"data"`
}

// Snapshot returns the registered subsystem snapshots in deterministic
// (name-sorted) order so HTTP responses and logs are reproducible.
func Snapshot() []NamedSnapshot {
	registryMu.RLock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	registryMu.RUnlock()
	sort.Strings(names)

	out := make([]NamedSnapshot, 0, len(names))
	registryMu.RLock()
	defer registryMu.RUnlock()
	for _, n := range names {
		s, ok := registry[n]
		if !ok {
			continue
		}
		out = append(out, NamedSnapshot{Name: n, Data: s.Snapshot()})
	}
	return out
}

// SnapshotMap is a convenience for callers (the web UI) that prefer a map
// keyed by subsystem name over the ordered slice from [Snapshot].
func SnapshotMap() map[string]any {
	snaps := Snapshot()
	m := make(map[string]any, len(snaps))
	for _, s := range snaps {
		m[s.Name] = s.Data
	}
	return m
}
