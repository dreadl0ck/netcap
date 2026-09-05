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
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	. "github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/types"
)

var disableDPI atomic.Bool

// Serialize flow tracking, classification, and native engine lifecycle.
var dpiMu sync.Mutex

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
	dpiMu.Lock()
	defer dpiMu.Unlock()
	if !disableDPI.Load() {
		return
	}

	log.Println(ansi.Yellow + "[DPI] Init() called" + ansi.Reset)

	var (
		selectedModules []Module
		enabledWrappers []wrappers.Wrapper
	)

	// Parse the modules string to determine which ones to enable
	moduleSet := parseModules(modules)

	// Create wrappers based on selection
	if moduleSet["lpi"] {
		lPI := wrappers.NewLPIWrapper()
		enabledWrappers = append(enabledWrappers, lPI)
		//log.Println("DPI: enabled LPI wrapper")
	}

	if moduleSet["ndpi"] {
		nDPI := wrappers.NewNDPIWrapper()
		enabledWrappers = append(enabledWrappers, nDPI)
		//log.Println("DPI: enabled nDPI wrapper")
	}

	// Configure wrapper module if any wrappers are enabled
	if len(enabledWrappers) > 0 {
		wm := wrappers.NewWrapperModule()
		wm.ConfigureModule(wrappers.WrapperModuleConfig{Wrappers: enabledWrappers})
		selectedModules = append(selectedModules, wm)
	}

	// Add go-dpi classifier module if selected
	if moduleSet["go"] {
		goDPI := classifiers.NewClassifierModule()
		selectedModules = append(selectedModules, goDPI)
		//log.Println("DPI: enabled go-dpi classifier")
		//dpiLog.Info("DPI: enabled go-dpi classifier")
	}

	// Set modules and initialize
	if len(selectedModules) == 0 {
		log.Println("DPI: no modules enabled, defaulting to all modules")
		// Default to all modules
		wm := wrappers.NewWrapperModule()
		wm.ConfigureModule(wrappers.WrapperModuleConfig{
			Wrappers: []wrappers.Wrapper{
				wrappers.NewLPIWrapper(),
				wrappers.NewNDPIWrapper(),
			},
		})
		selectedModules = append(selectedModules, wm, classifiers.NewClassifierModule())
	}

	godpi.SetModules(selectedModules)

	if err := godpi.Initialize(); err != nil {
		log.Fatal("goDPI initialization returned an error: ", err)
	}

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

// Destroy tears down godpi and frees the memory allocated for cgo.
// It also explicitly resets the internal flow tracker to release all tracked flows.
// Returned errors are logged to stdout.
// Concurrent calls are safe; already disabled engines are left untouched.
func Destroy() {
	dpiMu.Lock()
	defer dpiMu.Unlock()
	if disableDPI.Swap(true) {
		return
	}

	log.Println(ansi.Red + "[DPI] Destroy() called" + ansi.Reset)

	// Destroy modules and flow tracker
	// This calls types.DestroyCache() which flushes the flow cache
	// and nils the FlowTrackerInstance to allow GC
	for _, e := range godpi.Destroy() {
		if e != nil {
			fmt.Println(e)
		}
	}
}

// Reset tears down the current DPI state without reinitializing it.
func Reset(modules string) {

	disabled := disableDPI.Load()
	log.Printf(ansi.Red+"[DPI] Reset() called, disabled=%t"+ansi.Reset, disabled)

	if !disabled {

		log.Printf("[DPI] Resetting DPI state with modules: %s", modules)

		// Destroy will:
		// - Call godpi.Destroy() which calls types.DestroyCache()
		// - types.DestroyCache() flushes the cache and nils FlowTrackerInstance
		// - This releases all tracked flows and allows GC to reclaim memory
		Destroy()
	}

	log.Println(ansi.Red + "[DPI] Reset() returning" + ansi.Reset)
}

// GetProtocols returns a map of all the identified protocol names to a result datastructure
// packets are identified with libprotoident, nDPI and a few custom heuristics from godpi.
// Will return nil if dpi is disabled.
// Classification is invoked for each packet up to MaxPacketsPerFlow; godpi internally
// manages when to actually perform classification based on MinPacketsForClassification.
func GetProtocols(packet gopacket.Packet) map[string]ClassificationResult {

	if disableDPI.Load() {
		return nil
	}
	dpiMu.Lock()
	defer dpiMu.Unlock()
	if disableDPI.Load() {
		return nil
	}

	// Validate that the packet has a transport layer with valid endpoints
	// This prevents crashes when trying to process packets without proper transport layer data
	if packet.TransportLayer() == nil {
		return nil
	}

	// Check that transport endpoints have valid data
	// UDP/TCP endpoints need at least 2 bytes for the port number
	transportFlow := packet.TransportLayer().TransportFlow()
	if len(transportFlow.Src().Raw()) == 0 || len(transportFlow.Dst().Raw()) == 0 {
		return nil
	}

	//start := time.Now()
	//fmt.Println("DPI", packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())

	// Get packet flow and validate it to prevent null pointer dereferences
	// GetPacketFlow returns (flow, exists) where exists indicates if flow was already tracked
	flow, _ := godpi.GetPacketFlow(packet)

	// Validate that flow is not nil before accessing its methods
	// This prevents segmentation faults in the nDPI wrapper when DPI libraries
	// are not properly initialized or protocol data files are missing
	if flow == nil {
		return nil
	}

	// godpi only stores up to MaxPacketsPerFlow packets per flow.
	// Try classification on each packet up to this limit.
	// godpi internally checks MinPacketsForClassification before actually classifying.
	if flow.GetPacketCount() <= MaxPacketsPerFlow {
		results := godpi.ClassifyFlowAllModules(flow)

		//fmt.Println(packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow(), "complete", time.Since(start))
		//spew.Dump(results)

		// when using all modules we might receive duplicate classifications
		// so they will be deduplicated by protocol name before counting them later
		protocols := make(map[string]ClassificationResult)
		for _, r := range results {
			if r.Protocol == "UNKNOWN" || r.Protocol == "NO_PAYLOAD" {
				continue
			}
			protocols[string(r.Protocol)] = r
		}

		return protocols
	}

	return nil
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
