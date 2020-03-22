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
	"strconv"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"sync"

	"github.com/dreadl0ck/gopacket"
	"github.com/golang/protobuf/proto"
)

type AtomicTransportFlowMap struct {
	Items map[uint64]*types.TransportFlow
	sync.Mutex
}

var (
	TransportFlows = &AtomicTransportFlowMap{
		Items: make(map[uint64]*types.TransportFlow),
	}
	transportFlowEncoderInstance *CustomEncoder
	transportFlows               int64
)

var transportFlowEncoder = CreateCustomEncoder(types.Type_NC_TransportFlow, "TransportFlow", func(d *CustomEncoder) error {
	transportFlowEncoderInstance = d
	return nil
}, func(p gopacket.Packet) proto.Message {
	if ll := p.TransportLayer(); ll != nil {

		// lookup flow
		TransportFlows.Lock()
		if flow, ok := TransportFlows.Items[ll.TransportFlow().FastHash()]; ok {

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
				if v, err := strconv.Atoi(ll.TransportFlow().Src().String()); err == nil {
					flow.SrcPort = int32(v)
				}
				if v, err := strconv.Atoi(ll.TransportFlow().Dst().String()); err == nil {
					flow.DstPort = int32(v)
				}
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
			lf := &types.TransportFlow{}
			if v, err := strconv.Atoi(ll.TransportFlow().Src().String()); err == nil {
				lf.SrcPort = int32(v)
			}
			if v, err := strconv.Atoi(ll.TransportFlow().Dst().String()); err == nil {
				lf.DstPort = int32(v)
			}
			lf.UID = ll.TransportFlow().FastHash()
			lf.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)
			lf.Proto = ll.LayerType().String()
			lf.NumPackets = 1
			lf.TotalSize = int64(len(p.Data()))
			TransportFlows.Items[ll.TransportFlow().FastHash()] = lf

			// continuously flush flows
			transportFlows++
			if netFlows%flowFlushInterval == 0 {

				var selectFlows []*types.TransportFlow
				for id, f := range TransportFlows.Items {
					// flush entries whose last timestamp is flowTimeOut older than current packet
					if p.Metadata().Timestamp.Sub(utils.StringToTime(f.TimestampLast)) > flowTimeOut {
						selectFlows = append(selectFlows, f)
						// cleanup
						delete(TransportFlows.Items, id)
					}
				}

				// do this in background
				go func() {
					for _, f := range selectFlows {
						writeTransportFlow(f)
					}
				}()
			}
		}
		TransportFlows.Unlock()
	}
	return nil
}, func(e *CustomEncoder) error {
	if !e.writer.IsChanWriter {
		for _, f := range TransportFlows.Items {
			writeTransportFlow(f)
		}
	}
	return nil
})

func writeTransportFlow(f *types.TransportFlow) {
	atomic.AddInt64(&transportFlowEncoderInstance.numRecords, 1)
	err := transportFlowEncoderInstance.writer.Write(f)
	if err != nil {
		log.Fatal("failed to write audit record: ", err)
	}
}

func DumpTop5TransportFlows() {

	println("Top 5 Transport Layer Flows:")
	if len(TransportFlows.Items) == 0 {
		return
	}

	hits := make([]int64, len(TransportFlows.Items))
	for _, f := range TransportFlows.Items {
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
		flows = map[uint64]*types.TransportFlow{}
	)
	for uid, f := range TransportFlows.Items {
		if f.NumPackets >= bound {
			flows[uid] = f
		}
	}
	// print the highest volume flows in order
	for _, hitCount := range hits[len(hits)-numTop:] {
		for _, f := range flows {
			if f.NumPackets == hitCount {
				fmt.Printf("(%s %s -> %s (%d)\n", pad(f.Proto+")", 10), pad(strconv.Itoa(int(f.SrcPort)), 24), utils.Pad(strconv.Itoa(int(f.DstPort)), 24), f.NumPackets)
			}
		}
	}
	println()

}
