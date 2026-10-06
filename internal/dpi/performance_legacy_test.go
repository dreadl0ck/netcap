//go:build !nodpi

package dpi

import (
	"os"
	"strconv"
	"sync"
	"testing"

	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	dpitypes "github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
)

// DPI_BENCH_LEGACY=1 runs the pre-optimization integration with identical fixtures.
// DPI_BENCH_LEGACY=budget additionally caps attempts, isolating the replay/interop cost.
func setupPerformance(tb testing.TB, modules string) (func(gopacket.Packet) map[string]dpitypes.ClassificationResult, func()) {
	tb.Helper()
	Destroy()
	mode := os.Getenv("DPI_BENCH_LEGACY")
	if mode == "" {
		workers := 0
		if value := os.Getenv("DPI_BENCH_WORKERS"); value != "" {
			var err error
			workers, err = strconv.Atoi(value)
			if err != nil {
				tb.Fatal(err)
			}
		}
		InitWithConfig(modules, RuntimeConfig{Workers: workers})
		tb.Cleanup(Destroy)
		return GetProtocols, dpiPool.flush
	}
	selected := parseModules(modules)
	var enabled []wrappers.Wrapper
	if selected["lpi"] {
		enabled = append(enabled, wrappers.NewLPIWrapper())
	}
	if selected["ndpi"] {
		enabled = append(enabled, wrappers.NewNDPIWrapper())
	}
	var engines []dpitypes.Module
	if len(enabled) > 0 {
		m := wrappers.NewWrapperModule()
		m.ConfigureModule(wrappers.WrapperModuleConfig{Wrappers: enabled})
		engines = append(engines, m)
	}
	if selected["go"] {
		engines = append(engines, classifiers.NewClassifierModule())
	}
	godpi.SetModules(engines)
	if errs := godpi.Initialize(); len(errs) != 0 {
		tb.Fatal(errs)
	}
	tb.Cleanup(func() {
		if errs := godpi.Destroy(); len(errs) != 0 {
			tb.Error(errs)
		}
	})
	var mu sync.Mutex
	attempts := make(map[*dpitypes.Flow]int)
	return func(packet gopacket.Packet) map[string]dpitypes.ClassificationResult {
			mu.Lock()
			defer mu.Unlock()
			flow, _ := godpi.GetPacketFlow(packet)
			if mode == "budget" {
				if attempts[flow] >= dpitypes.MaxPacketsPerFlow {
					return nil
				}
				attempts[flow]++
			}
			if flow.GetPacketCount() <= dpitypes.MaxPacketsPerFlow {
				results := godpi.ClassifyFlowAllModules(flow)
				protocols := make(map[string]dpitypes.ClassificationResult)
				for _, r := range results {
					if r.Protocol != "UNKNOWN" && r.Protocol != "NO_PAYLOAD" {
						protocols[string(r.Protocol)] = r
					}
				}
				return protocols
			}
			return nil
		}, func() {
			mu.Lock()
			defer mu.Unlock()
			dpitypes.FlushTrackedFlows()
			clear(attempts)
		}
}
