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

//go:build !linux

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

