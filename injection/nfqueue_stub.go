//go:build !linux

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

