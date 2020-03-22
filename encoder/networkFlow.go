/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"fmt"
	"log"
	"sort"
	"sync/atomic"

	"sync"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"

	"github.com/dreadl0ck/gopacket"
	"github.com/golang/protobuf/proto"
)

type AtomicNetworkFlowMap struct {
	Items map[uint64]*types.NetworkFlow
	sync.Mutex
}

var (
	NetworkFlows = &AtomicNetworkFlowMap{
		Items: make(map[uint64]*types.NetworkFlow),
	}
	networkFlowEncoderInstance *CustomEncoder
	netFlows                   int64
)

var networkFlowEncoder = CreateCustomEncoder(types.Type_NC_NetworkFlow, "NetworkFlow", func(d *CustomEncoder) error {
	networkFlowEncoderInstance = d
	return nil
}, func(p gopacket.Packet) proto.Message {
	if ll := p.NetworkLayer(); ll != nil {

		// lookup flow
		NetworkFlows.Lock()
		if flow, ok := NetworkFlows.Items[ll.NetworkFlow().FastHash()]; ok {

			// flow exists. update fields
			calcDuration := false

			// check if received packet from the same flow
			// was captured BEFORE the flows first seen timestamp
			if !utils.StringToTime(flow.TimestampFirst).Before(p.Metadata().Timestamp) {

				calcDuration = true

				// if there is no last seen timestamp yet, simply swap the values
				// otherwise the previously stored TimestampFirst value would be lost
				if flow.TimestampLast == "" {
					flow.TimestampLast = flow.TimestampFirst
				}

				// rewrite first seen timestamp
				flow.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

				// rewrite source and destination parameters
				// since the first packet decides about the flow direction
				flow.SrcIP = ll.NetworkFlow().Src().String()
				flow.DstIP = ll.NetworkFlow().Dst().String()
			}

			// check if last timestamp was before the current packet
			if utils.StringToTime(flow.TimestampLast).Before(p.Metadata().Timestamp) {
				// current packet is newer
				// update last seen timestamp
				flow.TimestampLast = utils.TimeToString(p.Metadata().Timestamp)
				calcDuration = true
			} // else: do nothing, timestamp is still the oldest one

			flow.NumPackets++
			flow.TotalSize += int64(len(p.Data()))

			if calcDuration {
				flow.Duration = utils.StringToTime(flow.TimestampLast).Sub(utils.StringToTime(flow.TimestampFirst)).Nanoseconds()
			}
		} else {

			// create new flow
			lf := &types.NetworkFlow{}
			lf.DstIP = ll.NetworkFlow().Dst().String()
			lf.SrcIP = ll.NetworkFlow().Src().String()
			lf.UID = ll.NetworkFlow().FastHash()
			lf.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)
			lf.Proto = ll.LayerType().String()
			lf.NumPackets = 1
			lf.TotalSize = int64(len(p.Data()))
			NetworkFlows.Items[ll.NetworkFlow().FastHash()] = lf

			// continuously flush flows
			netFlows++
			if netFlows%flowFlushInterval == 0 {

				var selectFlows []*types.NetworkFlow
				for id, f := range NetworkFlows.Items {
					// flush entries whose last timestamp is flowTimeOut older than current packet
					if p.Metadata().Timestamp.Sub(utils.StringToTime(f.TimestampLast)) > flowTimeOut {
						selectFlows = append(selectFlows, f)
						// cleanup
						delete(NetworkFlows.Items, id)
					}
				}

				// do this in background
				go func() {
					for _, f := range selectFlows {
						writeNetworkFlow(f)
					}
				}()
			}
		}
		NetworkFlows.Unlock()
	}
	return nil
}, func(e *CustomEncoder) error {
	if !e.writer.IsChanWriter {
		for _, f := range NetworkFlows.Items {
			writeNetworkFlow(f)
		}
	}
	return nil
})

func writeNetworkFlow(f *types.NetworkFlow) {
	atomic.AddInt64(&networkFlowEncoderInstance.numRecords, 1)
	err := networkFlowEncoderInstance.writer.Write(f)
	if err != nil {
		log.Fatal("failed to write audit record: ", err)
	}
}

func DumpTop5NetworkFlows() {

	println("Top 5 Network Layer Flows:")
	if len(NetworkFlows.Items) == 0 {
		return
	}

	hits := make([]int64, len(NetworkFlows.Items))
	for _, f := range NetworkFlows.Items {
		hits = append(hits, f.NumPackets)
	}
	sort.Slice(hits, func(i int, j int) bool {
		return hits[i] < hits[j]
	})

	// in case there are less than 5 flows in total
	// make sure there no index out of range
	var numTop = 5
	if len(hits) < 5 {
		numTop = len(hits)
	}

	// collect highest vol. flow objects
	var (
		bound = hits[len(hits)-numTop]
		flows = map[uint64]*types.NetworkFlow{}
	)
	for uid, f := range NetworkFlows.Items {
		if f.NumPackets >= bound {
			flows[uid] = f
		}
	}
	// print the highest volume flows in order
	for _, hitCount := range hits[len(hits)-numTop:] {
		for _, f := range flows {
			if f.NumPackets == hitCount {
				fmt.Printf("(%s %s -> %s (%d)\n", pad(f.Proto+")", 10), pad(f.SrcIP, 24), utils.Pad(f.DstIP, 24), f.NumPackets)
			}
		}
	}
	println()

}
