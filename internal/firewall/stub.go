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

package firewall

import (
	"fmt"
	"runtime"
)

// NewManager returns an error on non-Linux platforms.
func NewManager(config *ManagerConfig) (*Manager, error) {
	return nil, fmt.Errorf("firewall management is only supported on Linux (current: %s)", runtime.GOOS)
}

// Manager is a stub for non-Linux platforms.
type Manager struct{}

// BlockIP is a stub.
func (m *Manager) BlockIP(ip string, config *BlockConfig) error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// BlockCIDR is a stub.
func (m *Manager) BlockCIDR(cidr string, config *BlockConfig) error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// UnblockIP is a stub.
func (m *Manager) UnblockIP(ip string) error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// UnblockCIDR is a stub.
func (m *Manager) UnblockCIDR(cidr string) error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// IsBlocked is a stub.
func (m *Manager) IsBlocked(ip string) bool {
	return false
}

// GetActiveBlocks is a stub.
func (m *Manager) GetActiveBlocks() []*BlockEntry {
	return nil
}

// GetStats is a stub.
func (m *Manager) GetStats() map[string]uint64 {
	return nil
}

// AddToWhitelist is a stub.
func (m *Manager) AddToWhitelist(target string) {}

// RemoveFromWhitelist is a stub.
func (m *Manager) RemoveFromWhitelist(target string) {}

// Flush is a stub.
func (m *Manager) Flush() error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// Close is a stub.
func (m *Manager) Close() error {
	return nil
}
