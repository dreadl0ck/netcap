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

package decoder

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

type flow struct {
	*types.Flow
	sync.Mutex
}

type atomicFlowMap struct {
	Items map[string]*flow
	sync.Mutex
}

func (a *atomicFlowMap) size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

type flowCustomDecoder struct {
	*customDecoder
	Flows *atomicFlowMap
}

var flowDecoder = &flowCustomDecoder{
	customDecoder: &customDecoder{
		Type:        types.Type_NC_Flow,
		Name:        "Flow",
		Description: "A flow represents uni-directional network communication between two hosts based on the combined link-, network- and transport layer identifiers",
	},
	Flows: &atomicFlowMap{
		Items: make(map[string]*flow),
	},
}

// PostInit is called after the decoder has been initialized.
func (fd *flowCustomDecoder) PostInit() error {
	// simply overwrite the handler with our custom one
	// this way the CustomEncoders default Decode() implementation will be used
	// (it takes care of applying config options and tracking stats)
	// but with our custom logic to handle the actual packet
	fd.Handler = fd.handlePacket

	return nil
}

// Destroy closes and flushes all writers and calls deinit if set.
func (fd *flowCustomDecoder) Destroy() (name string, size int64) {
	// call Deinit on FlowDecoder, instead of CustomDecoder
	err := fd.DeInit()
	if err != nil {
		panic(err)
	}

	return fd.writer.Close()
}

func (fd *flowCustomDecoder) handlePacket(p gopacket.Packet) proto.Message {
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
	fd.Flows.Lock()
	if f, ok := fd.Flows.Items[flowID]; ok {

		// flow exists. update fields
		calcDuration := false

		f.Lock()

		// check if received packet from the same flow
		// was captured BEFORE the flows first seen timestamp
		if !utils.StringToTime(f.TimestampFirst).Before(p.Metadata().Timestamp) {
			calcDuration = true

			// if there is no last seen timestamp yet, simply swap the values
			// otherwise the previously stored TimestampFirst value would be lost
			if f.TimestampLast == "" {
				f.TimestampLast = f.TimestampFirst
			}

			// rewrite timestamp
			f.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

			// rewrite source and destination parameters
			// since the first packet decides about the flow direction
			if ll := p.LinkLayer(); ll != nil {
				f.SrcMAC = ll.LinkFlow().Src().String()
				f.DstMAC = ll.LinkFlow().Dst().String()
			}
			if nl := p.NetworkLayer(); nl != nil {
				f.NetworkProto = nl.LayerType().String()
				f.SrcIP = nl.NetworkFlow().Src().String()
				f.DstIP = nl.NetworkFlow().Dst().String()
			}
			if tl := p.TransportLayer(); tl != nil {
				f.TransportProto = tl.LayerType().String()
				f.SrcPort = tl.TransportFlow().Src().String()
				f.DstPort = tl.TransportFlow().Dst().String()
			}
		}

		// check if last timestamp was before the current packet
		if utils.StringToTime(f.TimestampLast).Before(p.Metadata().Timestamp) {
			// current packet is newer
			// update last seen timestamp
			f.TimestampLast = utils.TimeToString(p.Metadata().Timestamp)
			calcDuration = true
		} // else: do nothing, timestamp is still the oldest one

		f.NumPackets++
		f.TotalSize += int32(len(p.Data()))

		// only calculate duration when timetamps have changed
		if calcDuration {
			f.Duration = utils.StringToTime(f.TimestampLast).Sub(utils.StringToTime(f.TimestampFirst)).Nanoseconds()
		}

		f.Unlock()
	} else {
		// create a new flow
		fl := &types.Flow{}
		fl.UID = calcMd5(flowID)
		fl.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

		if ll := p.LinkLayer(); ll != nil {
			fl.LinkProto = ll.LayerType().String()
			fl.SrcMAC = ll.LinkFlow().Src().String()
			fl.DstMAC = ll.LinkFlow().Dst().String()
		}
		if nl := p.NetworkLayer(); nl != nil {
			fl.NetworkProto = nl.LayerType().String()
			fl.SrcIP = nl.NetworkFlow().Src().String()
			fl.DstIP = nl.NetworkFlow().Dst().String()
		}
		if tl := p.TransportLayer(); tl != nil {
			fl.TransportProto = tl.LayerType().String()
			fl.SrcPort = tl.TransportFlow().Src().String()
			fl.DstPort = tl.TransportFlow().Dst().String()
		}
		if al := p.ApplicationLayer(); al != nil {
			fl.ApplicationProto = al.LayerType().String()
			fl.AppPayloadSize = int32(len(al.Payload()))
		}
		fd.Flows.Items[flowID] = &flow{
			Flow: fl,
		}

		flows := atomic.AddInt64(&stats.numFlows, 1)

		// continuously flush flows
		if conf.FlowFlushInterval != 0 && flows%int64(conf.FlowFlushInterval) == 0 {
			var selectFlows []*types.Flow
			for id, flw := range fd.Flows.Items {
				// flush entries whose last timestamp is flowTimeOut older than current packet
				if p.Metadata().Timestamp.Sub(utils.StringToTime(fl.TimestampLast)) > conf.FlowTimeOut {
					selectFlows = append(selectFlows, flw.Flow)
					// cleanup
					delete(fd.Flows.Items, id)
				}
			}

			// do this in background
			go func() {
				for _, flw := range selectFlows {
					fd.writeFlow(flw)
				}
			}()
		}
	}
	fd.Flows.Unlock()

	return nil
}

// DeInit will teardown and flush all remaining records.
// DeInit is called prior to teardown.
func (fd *flowCustomDecoder) DeInit() error {
	fd.Flows.Lock()
	for _, f := range fd.Flows.Items {
		f.Lock()
		fd.writeFlow(f.Flow)
		f.Unlock()
	}
	fd.Flows.Unlock()

	return nil
}

func (fd *flowCustomDecoder) writeFlow(f *types.Flow) {
	if conf.Export {
		f.Inc()
	}

	atomic.AddInt64(&fd.numRecords, 1)
	err := fd.writer.Write(f)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
