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
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/golang/protobuf/proto"
	"github.com/dreadl0ck/gopacket"
)

// AtomicConnMap contains all connections and provides synchronized access
type AtomicConnMap struct {
	Items map[string]*types.Connection
	sync.Mutex
}

// Size returns the number of elements in the Items map
func (a *AtomicConnMap) Size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

var (
	// Connections hold all connections
	Connections = &AtomicConnMap{
		Items: make(map[string]*types.Connection),
	}
	connEncoderInstance *CustomEncoder
	conns               int64

	// flags for flushing intervals
	flagConnFlushInterval = flag.Int("conn-flush-interval", 10000, "flush connections every X flows")
	flagConnTimeOut       = flag.Int("conn-timeout", 10, "close connections older than X seconds")

	connFlushInterval int64
	connTimeOut       time.Duration
)

// ConnectionID is a bidirectional connection
// between two devices over the network
// that includes the Link, Network and TransportLayer
type ConnectionID struct {
	LinkFlowID      uint64
	NetworkFlowID   uint64
	TransportFlowID uint64
}

func (c ConnectionID) String() string {
	return strconv.FormatUint(c.LinkFlowID, 10) + strconv.FormatUint(c.NetworkFlowID, 10) + strconv.FormatUint(c.TransportFlowID, 10)
}

var connectionEncoder = CreateCustomEncoder(types.Type_NC_Connection, "Connection", func(d *CustomEncoder) error {
	connEncoderInstance = d
	connFlushInterval = int64(*flagConnFlushInterval)
	connTimeOut = time.Second * time.Duration(*flagConnTimeOut)
	return nil
}, func(p gopacket.Packet) proto.Message {

	// assemble connectionID
	c := ConnectionID{}
	if ll := p.LinkLayer(); ll != nil {
		c.LinkFlowID = ll.LinkFlow().FastHash()
	}
	if nl := p.NetworkLayer(); nl != nil {
		c.NetworkFlowID = nl.NetworkFlow().FastHash()
	}
	if tl := p.TransportLayer(); tl != nil {
		c.TransportFlowID = tl.TransportFlow().FastHash()
	}

	// lookup flow
	Connections.Lock()
	if conn, ok := Connections.Items[c.String()]; ok {

		// conn exists. update fields
		calcDuration := false

		// check if received packet from the same flow
		// was captured BEFORE the flows first seen timestamp
		if !utils.StringToTime(conn.TimestampFirst).Before(p.Metadata().Timestamp) {

			calcDuration = true

			// rewrite timestamp
			conn.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

			// rewrite source and destination parameters
			// since the first packet decides about the flow direction
			if ll := p.LinkLayer(); ll != nil {
				conn.SrcMAC = ll.LinkFlow().Src().String()
				conn.DstMAC = ll.LinkFlow().Dst().String()
			}
			if nl := p.NetworkLayer(); nl != nil {
				conn.SrcIP = nl.NetworkFlow().Src().String()
				conn.DstIP = nl.NetworkFlow().Dst().String()
			}
			if tl := p.TransportLayer(); tl != nil {
				conn.SrcPort = tl.TransportFlow().Src().String()
				conn.DstPort = tl.TransportFlow().Dst().String()
			}
		}

		// check if last timestamp was before the current packet
		if utils.StringToTime(conn.TimestampLast).Before(p.Metadata().Timestamp) {
			// current packet is newer
			// update last seen timestamp
			conn.TimestampLast = utils.TimeToString(p.Metadata().Timestamp)
			calcDuration = true
		} // else: do nothing, timestamp is still the oldest one

		conn.NumPackets++
		conn.TotalSize += int32(len(p.Data()))

		// only calculate duration when timetamps have changed
		if calcDuration {
			conn.Duration = utils.StringToTime(conn.TimestampLast).Sub(utils.StringToTime(conn.TimestampFirst)).Nanoseconds()
		}
	} else {
		// create a new Connection
		conn := &types.Connection{}
		conn.UID = calcMd5(c.String())
		conn.TimestampFirst = utils.TimeToString(p.Metadata().Timestamp)

		if ll := p.LinkLayer(); ll != nil {
			conn.LinkProto = ll.LayerType().String()
			conn.SrcMAC = ll.LinkFlow().Src().String()
			conn.DstMAC = ll.LinkFlow().Dst().String()
		}
		if nl := p.NetworkLayer(); nl != nil {
			conn.NetworkProto = nl.LayerType().String()
			conn.SrcIP = nl.NetworkFlow().Src().String()
			conn.DstIP = nl.NetworkFlow().Dst().String()
		}
		if tl := p.TransportLayer(); tl != nil {
			conn.TransportProto = tl.LayerType().String()
			conn.SrcPort = tl.TransportFlow().Src().String()
			conn.DstPort = tl.TransportFlow().Dst().String()
		}
		if al := p.ApplicationLayer(); al != nil {
			conn.ApplicationProto = al.LayerType().String()
			conn.AppPayloadSize = int32(len(al.Payload()))
		}
		Connections.Items[c.String()] = conn

		conns++

		// flush
		if conns%connFlushInterval == 0 {

			var selectConns []*types.Connection
			for id, c := range Connections.Items {
				// flush entries whose last timestamp is connTimeOut older than current packet
				if p.Metadata().Timestamp.Sub(utils.StringToTime(c.TimestampLast)) > connTimeOut {
					selectConns = append(selectConns, c)
					// cleanup
					delete(Connections.Items, id)
				}
			}

			// flush selection in background
			go func() {
				for _, c := range selectConns {
					writeConn(c)
				}
			}()
		}
	}
	Connections.Unlock()
	return nil
}, func(e *CustomEncoder) error {
	if !e.writer.IsChanWriter {
		for _, c := range Connections.Items {
			writeConn(c)
		}
	}
	return nil
})

// writeConn writes the connection
func writeConn(c *types.Connection) {

	if connEncoderInstance.export {
		c.Inc()
	}

	atomic.AddInt64(&connEncoderInstance.numRecords, 1)
	err := connEncoderInstance.writer.Write(c)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
