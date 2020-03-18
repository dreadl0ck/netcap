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

func Destroy() {
	for _, e := range godpi.Destroy() {
		if e != nil {
			fmt.Println(e)
		}
	}
}

func GetProtocols(packet gopacket.Packet) map[string]struct{} {

	var uniqueResults = make(map[string]struct{})
	flow, _ := godpi.GetPacketFlow(packet)
	results := godpi.ClassifyFlowAllModules(flow)

	// when using all modules we might receive duplicate classifications
	// so they will be deduplicated before counting them
	for _, r := range results {
		uniqueResults[string(r.Protocol)] = struct{}{}
	}

	return uniqueResults
}
