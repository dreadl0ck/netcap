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
	"sort"
	"sync"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
)

type AtomicLinkFlowMap struct {
	Items map[uint64]*types.LinkFlow
	sync.Mutex
}

var (
	LinkFlows = &AtomicLinkFlowMap{
		Items: make(map[uint64]*types.LinkFlow),
	}
	linkFlowEncoderInstance *CustomEncoder
	linkFlows               int64
)

var linkFlowEncoder = CreateCustomEncoder(types.Type_NC_LinkFlow, "LinkFlow", func(d *CustomEncoder) error {
	linkFlowEncoderInstance = d
	return nil
}, func(p gopacket.Packet) proto.Message {
	if ll := p.LinkLayer(); ll != nil {

		// lookup flow
		LinkFlows.Lock()
		if flow, ok := LinkFlows.Items[ll.LinkFlow().FastHash()]; ok {

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
				flow.SrcMAC = ll.LinkFlow().Src().String()
				flow.DstMAC = ll.LinkFlow().Dst().String()
			}

			// check if last timestamp was before the current packet
			if utils.StringToTime(flow.TimestampLast).Before(p.Metadata().Timestamp) {
				// current packet is newer
				// update last seen timestamp
				flow.TimestampLast = utils.TimeToString(p.Metadata().Timestamp)
				calcDuration = true
			} // else: do nothing, timestamp is still the oldest one

			flow.NumPackets++
			flow.Size += int64(len(p.Data()))

			if calcDuration {
				flow.Duration = utils.StringToTime(flow.TimestampLast).Sub(utils.StringToTime(flow.TimestampFirst)).Nanoseconds()
			}
		} else {

			// create a new flow
			lf := &types.LinkFlow{}
			lf.DstMAC = ll.LinkFlow().Dst().String()
			lf.SrcMAC = ll.LinkFlow().Src().String()
			lf.UID = ll.LinkFlow().FastHash()
			lf.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)
			lf.Proto = ll.LayerType().String()
			lf.NumPackets = 1
			lf.Size = int64(len(p.Data()))
			LinkFlows.Items[ll.LinkFlow().FastHash()] = lf

			// continuously flush flows
			linkFlows++
			if linkFlows%flowFlushInterval == 0 {

				var selectFlows []*types.LinkFlow
				for id, f := range LinkFlows.Items {
					// flush entries whose last timestamp is flowTimeOut older than current packet
					if p.Metadata().Timestamp.Sub(utils.StringToTime(f.TimestampLast)) > flowTimeOut {
						selectFlows = append(selectFlows, f)
						// cleanup
						delete(LinkFlows.Items, id)
					}
				}

				// do this in background
				go func() {
					for _, f := range selectFlows {
						writeLinkFlow(f)
					}
				}()
			}
		}
		LinkFlows.Unlock()
	}
	return nil
}, func(d *CustomEncoder) error {
	if d.cWriter == nil {
		for _, f := range LinkFlows.Items {
			if linkFlowEncoderInstance.csv {
				_, err := linkFlowEncoderInstance.csvWriter.WriteRecord(f)
				if err != nil {
					errorMap.Inc(err.Error())
				}
			} else {
				// write protobuf
				err := linkFlowEncoderInstance.dWriter.PutProto(f)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
})

func writeLinkFlow(f *types.LinkFlow) {
	if linkFlowEncoderInstance.csv {
		_, err := linkFlowEncoderInstance.csvWriter.WriteRecord(f)
		if err != nil {
			errorMap.Inc(err.Error())
		}
	} else {
		// write protobuf
		err := linkFlowEncoderInstance.aWriter.PutProto(f)
		if err != nil {
			panic(err)
		}
	}
}

func DumpTop5LinkFlows() {

	println("Top 5 Link Layer Flows:")
	if len(LinkFlows.Items) == 0 {
		return
	}

	hits := make([]int64, len(LinkFlows.Items))
	for _, f := range LinkFlows.Items {
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
		flows = map[uint64]*types.LinkFlow{}
	)
	for uid, f := range LinkFlows.Items {
		if f.NumPackets >= bound {
			flows[uid] = f
		}
	}
	// print the highest volume flows in order
	for _, hitCount := range hits[len(hits)-numTop:] {
		for _, f := range flows {
			if f.NumPackets == hitCount {
				fmt.Printf("(%s %s -> %s (%d)\n", pad(f.Proto+")", 10), pad(f.SrcMAC, 24), utils.Pad(f.DstMAC, 24), f.NumPackets)
			}
		}
	}
	println()

}
