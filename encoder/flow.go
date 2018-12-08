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
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
)

type AtomicFlowMap struct {
	Items map[string]*types.Flow
	sync.Mutex
}

func (a *AtomicFlowMap) Size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

var (
	Flows = &AtomicFlowMap{
		Items: make(map[string]*types.Flow),
	}
	flowEncoderInstance *CustomEncoder
	flows               int64

	flagFlowFlushInterval = flag.Int("flow-flush-interval", 2000, "flush flows every X flows")
	flagFlowTimeOut       = flag.Int("flow-timeout", 30, "close flows older than X seconds")
)

var (
	flowFlushInterval = int64(*flagFlowFlushInterval)
	flowTimeOut       = time.Second * time.Duration(*flagFlowTimeOut)
)

var FlowEncoder = CreateCustomEncoder(types.Type_NC_Flow, "Flow", func(d *CustomEncoder) error {
	flowEncoderInstance = d
	return nil
}, func(p gopacket.Packet) proto.Message {

	// get identifier
	var (
		net       gopacket.Flow
		transport gopacket.Flow
	)
	if nl := p.NetworkLayer(); nl != nil {
		net = nl.NetworkFlow()
	}
	if tl := p.TransportLayer(); tl != nil {
		transport = tl.TransportFlow()
	}
	flowID := fmt.Sprintf("%s:%s", net, transport)

	// lookup flow
	Flows.Lock()
	if flow, ok := Flows.Items[flowID]; ok {

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

			// rewrite timestamp
			flow.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

			// rewrite source and destination parameters
			// since the first packet decides about the flow direction
			if ll := p.LinkLayer(); ll != nil {
				flow.SrcMAC = ll.LinkFlow().Src().String()
				flow.DstMAC = ll.LinkFlow().Dst().String()
			}
			if nl := p.NetworkLayer(); nl != nil {
				flow.NetworkProto = nl.LayerType().String()
				flow.SrcIP = nl.NetworkFlow().Src().String()
				flow.DstIP = nl.NetworkFlow().Dst().String()
			}
			if tl := p.TransportLayer(); tl != nil {
				flow.TransportProto = tl.LayerType().String()
				flow.SrcPort = tl.TransportFlow().Src().String()
				flow.DstPort = tl.TransportFlow().Dst().String()
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
		flow.Size += int32(len(p.Data()))

		// only calculate duration when timetamps have changed
		if calcDuration {
			flow.Duration = utils.StringToTime(flow.TimestampLast).Sub(utils.StringToTime(flow.TimestampFirst)).Nanoseconds()
		}
	} else {
		// create a new flow
		f := &types.Flow{}
		f.UID = calcMd5(flowID)
		f.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

		if ll := p.LinkLayer(); ll != nil {
			f.LinkProto = ll.LayerType().String()
			f.SrcMAC = ll.LinkFlow().Src().String()
			f.DstMAC = ll.LinkFlow().Dst().String()
		}
		if nl := p.NetworkLayer(); nl != nil {
			f.NetworkProto = nl.LayerType().String()
			f.SrcIP = nl.NetworkFlow().Src().String()
			f.DstIP = nl.NetworkFlow().Dst().String()
			net = nl.NetworkFlow()
		}
		if tl := p.TransportLayer(); tl != nil {
			f.TransportProto = tl.LayerType().String()
			f.SrcPort = tl.TransportFlow().Src().String()
			f.DstPort = tl.TransportFlow().Dst().String()
			transport = tl.TransportFlow()
		}
		if al := p.ApplicationLayer(); al != nil {
			f.ApplicationProto = al.LayerType().String()
			f.AppPayloadSize = int32(len(al.Payload()))
		}
		Flows.Items[flowID] = f

		// continuously flush flows
		flows++
		if flows%flowFlushInterval == 0 {

			var selectFlows []*types.Flow
			for id, f := range Flows.Items {
				// flush entries whose last timestamp is flowTimeOut older than current packet
				if p.Metadata().Timestamp.Sub(utils.StringToTime(f.TimestampLast)) > flowTimeOut {
					selectFlows = append(selectFlows, f)
					// cleanup
					delete(Flows.Items, id)
				}
			}

			// do this in background
			go func() {
				for _, f := range selectFlows {
					writeFlow(f)
				}
			}()
		}
	}
	Flows.Unlock()
	return nil
}, func(d *CustomEncoder) error {
	if d.cWriter == nil {
		for _, f := range Flows.Items {
			writeFlow(f)
		}
	}
	return nil
})

func writeFlow(f *types.Flow) {
	if flowEncoderInstance.csv {
		_, err := flowEncoderInstance.csvWriter.WriteRecord(f)
		if err != nil {
			errorMap.Inc(err.Error())
		}
	} else {
		// write protobuf
		err := flowEncoderInstance.aWriter.PutProto(f)
		if err != nil {
			panic(err)
		}
	}
}
