// +build !windows

package dpi

import (
	"fmt"
	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/gopacket"
	"log"
)

var disableDPI = false

func Init() {
	var (
		nDPI = wrappers.NewNDPIWrapper()
		lPI = wrappers.NewLPIWrapper()
		goDPI = classifiers.NewClassifierModule()
		wm = wrappers.NewWrapperModule()
	)

	// init DPI
	wm.ConfigureModule(wrappers.WrapperModuleConfig{Wrappers: []wrappers.Wrapper{nDPI, lPI}})
	godpi.SetModules([]types.Module{wm, goDPI})
	if err := godpi.Initialize(); err != nil {
		log.Fatal("goDPI initialization returned error: ", err)
	}
}

// Destroy tears down godpi and frees the memory allocated for cgo
// returned errors are logged to stdout
func Destroy() {
	for _, e := range godpi.Destroy() {
		if e != nil {
			fmt.Println(e)
		}
	}
}

// GetProtocols returns a map of all the identified protocol names
// to the accumulated number of hits for each protocol
// packets are identified with libprotoident, nDPI and a few custom heuristics from godpi
func GetProtocols(packet gopacket.Packet) (map[string]types.ClassificationResult) {

	protocols := make(map[string]types.ClassificationResult)

	if disableDPI {
		return protocols
	}

	flow, _ := godpi.GetPacketFlow(packet)
	results := godpi.ClassifyFlowAllModules(flow)

	// when using all modules we might receive duplicate classifications
	// so they will be deduplicated by protocol name before counting them later
	for _, r := range results {
		protocols[string(r.Protocol)] = r
	}

	return protocols
}
