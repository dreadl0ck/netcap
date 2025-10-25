//go:build (!windows && ignore) || !nodpi
// +build !windows,ignore !nodpi

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

// Package dpi implements an interface for application layer classification via bindings to nDPI and libprotoident
package dpi

import (
	"fmt"
	"log"
	"strings"
	"time"

	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	. "github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/types"
)

var disableDPI = true

const categoryUnknown = "UNKNOWN"

// IsEnabled will return true if goDPI has been initialized
func IsEnabled() bool {
	return !disableDPI
}

// Init initializes the deep packet inspection engines.
// modules is a comma-separated list of modules to enable: lpi, ndpi, go
// If empty, all modules will be enabled.
func Init(modules string) {
	// Guard against double initialization - if DPI is already enabled, skip
	if !disableDPI {
		log.Println("DPI: already initialized, skipping re-initialization")
		return
	}

	disableDPI = false

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
		log.Println("DPI: enabled LPI wrapper")
	}

	if moduleSet["ndpi"] {
		nDPI := wrappers.NewNDPIWrapper()
		enabledWrappers = append(enabledWrappers, nDPI)
		log.Println("DPI: enabled nDPI wrapper")
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
		log.Println("DPI: enabled go-dpi classifier")
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
	parts := strings.Split(modules, ",")
	for _, part := range parts {
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
func Destroy() {
	// Only destroy if DPI is actually enabled
	if disableDPI {
		return
	}

	// Destroy modules and flow tracker
	// This calls types.DestroyCache() which flushes the flow cache
	// and nils the FlowTrackerInstance to allow GC
	for _, e := range godpi.Destroy() {
		if e != nil {
			fmt.Println(e)
		}
	}

	// Reset the flag so DPI can be re-initialized
	disableDPI = true
}

// Reset destroys the current DPI state and reinitializes it.
// This should be called when resetting state between processing different files.
// It performs the following cleanup:
//  1. Destroys all DPI modules (nDPI, LPI, go-dpi)
//  2. Flushes and nils the FlowTrackerInstance (releases all tracked flows)
//  3. Waits for C libraries to release memory
//  4. Reinitializes with the same modules
func Reset(modules string) {
	if !disableDPI {
		// Destroy will:
		// - Call godpi.Destroy() which calls types.DestroyCache()
		// - types.DestroyCache() flushes the cache and nils FlowTrackerInstance
		// - This releases all tracked flows and allows GC to reclaim memory
		Destroy()

		// Allow time for C libraries to fully release memory
		// This is important because nDPI and LPI use C memory allocation
		// which may not be immediately returned to the OS
		time.Sleep(10 * time.Millisecond)

		// Initialize fresh DPI state with new FlowTrackerInstance
		Init(modules)
	}
}

// GetProtocols returns a map of all the identified protocol names to a result datastructure
// packets are identified with libprotoident, nDPI and a few custom heuristics from godpi.
// Will return nil if dpi is disabled, or if flow is not yet ready to be classified (need 10 packets).
func GetProtocols(packet gopacket.Packet) map[string]ClassificationResult {

	if disableDPI {
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

	flow, _ := godpi.GetPacketFlow(packet)
	if flow.GetPacketCount() == 10 {
		results := godpi.ClassifyFlowAllModules(flow)

		//fmt.Println(packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow(), "complete", time.Since(start))
		//spew.Dump(results)

		// when using all modules we might receive duplicate classifications
		// so they will be deduplicated by protocol name before counting them later
		protocols := make(map[string]ClassificationResult)
		for _, r := range results {
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
