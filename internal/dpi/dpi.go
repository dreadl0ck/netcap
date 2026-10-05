//go:build (!windows && ignore) || !nodpi

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

// Package dpi implements an interface for application layer classification via bindings to nDPI and libprotoident
package dpi

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	. "github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/types"
)

var disableDPI atomic.Bool

// Lifecycle writes exclude classification; individual contexts are locked per shard.
var dpiMu sync.RWMutex
var dpiPool *incrementalPool

// Cache for module protocols to avoid re-initializing wrappers
var (
	moduleProtocolsCache     map[string][]string
	moduleProtocolsCacheLock sync.RWMutex
	moduleProtocolsCached    atomic.Bool
)

func init() {
	// Initialize disableDPI to true (DPI is disabled by default until Init() is called)
	// This prevents crashes when GetProtocols is called before DPI is initialized
	disableDPI.Store(true)
}

const categoryUnknown = "UNKNOWN"

// IsEnabled will return true if goDPI has been initialized
func IsEnabled() bool {
	return !disableDPI.Load()
}

// Init initializes the deep packet inspection engines.
// modules is a comma-separated list of modules to enable: lpi, ndpi, go
// If empty, all modules will be enabled.
// This function is thread-safe and will only execute once if called concurrently.
func Init(modules string) {
	InitWithConfig(modules, RuntimeConfig{})
}

func InitWithConfig(modules string, config RuntimeConfig) {
	dpiMu.Lock()
	defer dpiMu.Unlock()
	if !disableDPI.Load() {
		return
	}

	log.Println(ansi.Yellow + "[DPI] Init() called" + ansi.Reset)

	moduleSet := parseModules(modules)
	if len(moduleSet) == 0 {
		log.Println("DPI: no modules enabled, defaulting to all modules")
		moduleSet = parseModules("")
	}
	pool, err := configuredIncrementalPool(moduleSet, config)
	if err != nil {
		log.Fatal("DPI initialization returned an error: ", err)
	}
	dpiPool = pool

	// Enable DPI after successful initialization
	disableDPI.Store(false)

	log.Println(ansi.Yellow + "[DPI] Init() done" + ansi.Reset)
}

// parseModules parses a comma-separated list of module names and returns a set.
// Valid modules are: lpi, ndpi, go
// If the input is empty, all modules are enabled.
func parseModules(modules string) map[string]bool {
	moduleSet := make(map[string]bool)

	// If empty, enable all
	if modules == "" {
		moduleSet["lpi"] = true
		moduleSet["ndpi"] = true
		moduleSet["go"] = true
		return moduleSet
	}

	// Parse comma-separated values
	parts := strings.SplitSeq(modules, ",")
	for part := range parts {
		module := strings.TrimSpace(strings.ToLower(part))
		switch module {
		case "lpi":
			moduleSet["lpi"] = true
		case "ndpi":
			moduleSet["ndpi"] = true
		case "go":
			moduleSet["go"] = true
		default:
			log.Printf("DPI: warning: unknown module '%s', valid modules are: lpi, ndpi, go", part)
		}
	}

	return moduleSet
}

// Destroy releases native contexts and all tracked flow state.
// Concurrent calls are safe; already disabled engines are left untouched.
func Destroy() {
	dpiMu.Lock()
	defer dpiMu.Unlock()
	if disableDPI.Swap(true) {
		return
	}

	log.Println(ansi.Red + "[DPI] Destroy() called" + ansi.Reset)

	if dpiPool != nil {
		dpiPool.close()
		dpiPool = nil
	}
}

// Reset tears down the current DPI state without reinitializing it.
func Reset(modules string) {

	disabled := disableDPI.Load()
	log.Printf(ansi.Red+"[DPI] Reset() called, disabled=%t"+ansi.Reset, disabled)

	if !disabled {

		log.Printf("[DPI] Resetting DPI state with modules: %s", modules)

		Destroy()
	}

	log.Println(ansi.Red + "[DPI] Reset() returning" + ansi.Reset)
}

// GetProtocols returns a map of all the identified protocol names to a result datastructure
// packets are identified with libprotoident, nDPI and a few custom heuristics from godpi.
// Will return nil if dpi is disabled.
// Native engines keep incremental state until detection or the inspection budget.
func GetProtocols(packet gopacket.Packet) map[string]ClassificationResult {

	if disableDPI.Load() {
		return nil
	}
	dpiMu.RLock()
	defer dpiMu.RUnlock()
	if disableDPI.Load() {
		return nil
	}

	return dpiPool.classify(packet)
}

// NewProto initializes a new protocol.
func NewProto(res *ClassificationResult) *types.Protocol {
	return &types.Protocol{
		Packets:  1,
		Category: getCategoryString(res.Class),
	}
}

func getCategoryString(in Category) string {
	if in == "" {
		return categoryUnknown
	}
	return string(in)
}

// GetModuleProtocols returns a map of module names to their supported protocols
// using the new GetSupportedProtocols APIs introduced in go-dpi v1.3.0
func GetModuleProtocols() map[string][]string {
	// Fast path: return cached results if available
	if moduleProtocolsCached.Load() {
		moduleProtocolsCacheLock.RLock()
		defer moduleProtocolsCacheLock.RUnlock()

		// Return a copy to prevent external modification
		result := make(map[string][]string, len(moduleProtocolsCache))
		for k, v := range moduleProtocolsCache {
			protocols := make([]string, len(v))
			copy(protocols, v)
			result[k] = protocols
		}
		log.Printf("[DPI] GetModuleProtocols returning %d modules from cache", len(result))
		return result
	}

	// Slow path: initialize temporary wrappers to get protocol lists
	moduleProtocolsCacheLock.Lock()
	defer moduleProtocolsCacheLock.Unlock()

	// Double-check in case another goroutine initialized while we waited for lock
	if moduleProtocolsCached.Load() {
		result := make(map[string][]string, len(moduleProtocolsCache))
		for k, v := range moduleProtocolsCache {
			protocols := make([]string, len(v))
			copy(protocols, v)
			result[k] = protocols
		}
		return result
	}

	result := make(map[string][]string)

	// Get protocols from nDPI wrapper
	// Initialize a temporary instance just to get the protocol list
	ndpiWrapper := wrappers.NewNDPIWrapper()
	// initResult := ndpiWrapper.InitializeWrapper()
	// log.Printf("[DPI] nDPI InitializeWrapper returned: %d", initResult)
	// if initResult == 0 {
	protocols := ndpiWrapper.GetSupportedProtocols()
	log.Printf("[DPI] nDPI GetSupportedProtocols returned %d protocols", len(protocols))
	if len(protocols) > 0 {
		ndpiProtocols := make([]string, len(protocols))
		for i, p := range protocols {
			ndpiProtocols[i] = string(p)
		}
		result["ndpi"] = ndpiProtocols
	}
	//ndpiWrapper.DestroyWrapper()
	// } else {
	// 	log.Printf("[DPI] nDPI initialization failed with code: %d", initResult)
	// }

	// Get protocols from LPI wrapper
	// Initialize a temporary instance just to get the protocol list
	lpiWrapper := wrappers.NewLPIWrapper()
	// lpiInitResult := lpiWrapper.InitializeWrapper()
	// log.Printf("[DPI] LPI InitializeWrapper returned: %d", lpiInitResult)
	// if lpiInitResult == 0 {
	protocols = lpiWrapper.GetSupportedProtocols()
	log.Printf("[DPI] LPI GetSupportedProtocols returned %d protocols", len(protocols))
	if len(protocols) > 0 {
		lpiProtocols := make([]string, len(protocols))
		for i, p := range protocols {
			lpiProtocols[i] = string(p)
		}
		result["lpi"] = lpiProtocols
	}
	//lpiWrapper.DestroyWrapper()
	// } else {
	// 	log.Printf("[DPI] LPI initialization failed with code: %d", lpiInitResult)
	// }

	// Get protocols from go-dpi classifiers
	// Initialize a temporary instance just to get the protocol list
	goClassifier := classifiers.NewClassifierModule()
	// err := goClassifier.Initialize()
	// log.Printf("[DPI] go-dpi classifier Initialize returned error: %v", err)
	// if err == nil {
	protocols = goClassifier.GetSupportedProtocols()
	log.Printf("[DPI] go-dpi GetSupportedProtocols returned %d protocols", len(protocols))
	if len(protocols) > 0 {
		goProtocols := make([]string, len(protocols))
		for i, p := range protocols {
			goProtocols[i] = string(p)
		}
		result["go"] = goProtocols
	}
	//goClassifier.Destroy()
	// } else {
	// 	log.Printf("[DPI] go-dpi classifier initialization failed: %v", err)
	// }

	// Cache the result
	moduleProtocolsCache = result
	moduleProtocolsCached.Store(true)

	log.Printf("[DPI] GetModuleProtocols cached %d modules with protocols", len(result))
	return result
}
