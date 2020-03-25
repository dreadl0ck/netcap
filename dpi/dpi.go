// +build !windows

package dpi

import (
	"fmt"
	"log"
	"time"

	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/gopacket"
)

var disableDPI = true

func Init() {
	var (
		//nDPI  = wrappers.NewNDPIWrapper()
		lPI   = wrappers.NewLPIWrapper()
		//goDPI = classifiers.NewClassifierModule()
		wm    = wrappers.NewWrapperModule()
	)

	// init DPI
	wm.ConfigureModule(wrappers.WrapperModuleConfig{Wrappers: []wrappers.Wrapper{lPI}})
	godpi.SetModules([]types.Module{wm})
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

// GetProtocols returns a map of all the identified protocol names to a result datastructure
// packets are identified with libprotoident, nDPI and a few custom heuristics from godpi
func GetProtocols(packet gopacket.Packet) map[string]types.ClassificationResult {

	protocols := make(map[string]types.ClassificationResult)

	if disableDPI {
		return protocols
	}

	//start := time.Now()
	//fmt.Println("DPI", packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())

	flow, _ := godpi.GetPacketFlow(packet)
	results := godpi.ClassifyFlowAllModules(flow)

	//fmt.Println(packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow(), "complete", time.Since(start))

	// when using all modules we might receive duplicate classifications
	// so they will be deduplicated by protocol name before counting them later
	for _, r := range results {
		protocols[string(r.Protocol)] = r
	}

	return protocols
}

// GetProtocolsTimeout returns a map of all the identified protocol names to a result datastructure
// packets are identified with libprotoident, nDPI and a few custom heuristics from godpi
// this function spawn a goroutine to allow setting a timeout for each packet
func GetProtocolsTimeout(packet gopacket.Packet) map[string]types.ClassificationResult {

	protocols := make(map[string]types.ClassificationResult)

	if disableDPI {
		return protocols
	}

	var (
		results = make(chan []types.ClassificationResult, 1)
	)
	go func() {
		flow, _ := godpi.GetPacketFlow(packet)
		results <- godpi.ClassifyFlowAllModules(flow)
	}()

	//start := time.Now()

	select {
	case res := <-results:

		//fmt.Println("got result after", time.Since(start))

		// when using all modules we might receive duplicate classifications
		// so they will be deduplicated by protocol name before counting them later
		for _, r := range res {
			protocols[string(r.Protocol)] = r
		}
	case <-time.After(3 * time.Second):
		fmt.Println("get protocols timeout", packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())
	}

	return protocols
}
