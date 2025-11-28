//go:build !linux

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

package injection

import (
	"fmt"
	"runtime"
)

// NFQueueHandler is a stub for non-Linux platforms.
type NFQueueHandler struct{}

// RawInjector is a stub for non-Linux platforms.
type RawInjector struct{}

// NewNFQueueHandler returns an error on non-Linux platforms.
func NewNFQueueHandler(engine *Engine, config *EngineConfig) (*NFQueueHandler, error) {
	return nil, fmt.Errorf("nfqueue is only supported on Linux (current OS: %s)", runtime.GOOS)
}

// Start returns an error on non-Linux platforms.
func (h *NFQueueHandler) Start() error {
	return fmt.Errorf("nfqueue is only supported on Linux (current OS: %s)", runtime.GOOS)
}

// Stop returns nil on non-Linux platforms.
func (h *NFQueueHandler) Stop() error {
	return nil
}

// GetStats returns zeros on non-Linux platforms.
func (h *NFQueueHandler) GetStats() (received, accepted, dropped, modified uint64) {
	return 0, 0, 0, 0
}

// NewRawInjector returns an error on non-Linux platforms.
func NewRawInjector(iface string) (*RawInjector, error) {
	return nil, fmt.Errorf("raw packet injection is only supported on Linux (current OS: %s)", runtime.GOOS)
}

// InjectPacket returns an error on non-Linux platforms.
func (ri *RawInjector) InjectPacket(data []byte) error {
	return fmt.Errorf("raw packet injection is only supported on Linux (current OS: %s)", runtime.GOOS)
}

// Close returns nil on non-Linux platforms.
func (ri *RawInjector) Close() error {
	return nil
}

// IsNFQueueSupported returns false on non-Linux platforms.
func IsNFQueueSupported() bool {
	return false
}
