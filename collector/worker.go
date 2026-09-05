/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// packetContextPool reuses PacketContext objects to reduce GC pressure.
var packetContextPool = sync.Pool{
	New: func() any { return &types.PacketContext{} },
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func (c *Collector) worker(assembler *reassembly.Assembler) chan gopacket.Packet {
	var (
		in  = make(chan gopacket.Packet, c.config.PacketBufferSize)
		pkt gopacket.Packet

		errLayer gopacket.ErrorLayer
		err      error

		decoders  []*packet.GoPacketDecoder
		dec       *packet.GoPacketDecoder
		customDec packet.DecoderAPI
		ok        bool

		netLayer       gopacket.NetworkLayer
		transportLayer gopacket.TransportLayer
		layer          gopacket.Layer
	)

	allProtos := c.allProtosAtomic.NewShard()
	unknownProtos := c.unknownProtosAtomic.NewShard()

	// start worker
	go func() {
		for pkt = range in {
			// nil packet is used to exit goroutine
			if pkt == nil {
				return
			}

			pkt.Metadata().Timestamp = pkt.Metadata().CaptureInfo.Timestamp
			pkt.Metadata().Length = pkt.Metadata().CaptureInfo.Length
			pkt.Metadata().CaptureLength = pkt.Metadata().CaptureInfo.CaptureLength

			// pass packet to reassembly
			if c.config.ReassembleConnections {
				t := time.Now()
				tcp.ReassemblePacket(pkt, assembler)
				duration := time.Since(t)
				reassemblyTime.WithLabelValues().Set(float64(duration.Nanoseconds()))
				c.perfTracker.RecordReassembly(duration)
			}

			// create context for packet (reuse from pool to reduce GC pressure)
			ctx := packetContextPool.Get().(*types.PacketContext)
			*ctx = types.PacketContext{}

			// Always calculate Community ID v1 for cross-tool correlation
			ctx.CommunityID = packet.CalcCommunityID(pkt)

			if c.config.DecoderConfig.AddContext {
				netLayer = pkt.NetworkLayer()
				transportLayer = pkt.TransportLayer()

				if netLayer != nil {
					if len(netLayer.NetworkFlow().Src().Raw()) > 0 {
						ctx.SrcIP = netLayer.NetworkFlow().Src().String()
					}
					if len(netLayer.NetworkFlow().Dst().Raw()) > 0 {
						ctx.DstIP = netLayer.NetworkFlow().Dst().String()
					}
				}

				if transportLayer != nil {
					ctx.SrcPort = utils.DecodePort(transportLayer.TransportFlow().Src().Raw())
					ctx.DstPort = utils.DecodePort(transportLayer.TransportFlow().Dst().Raw())
				}
			}

			// iterate over all layers
			for _, layer = range pkt.Layers() {

				// cache the layer type string to avoid repeated String() allocations
				layerTypeStr := layer.LayerType().String()

				// increment counter for layer type
				allProtos.Inc(layerTypeStr)

				if c.config.DecoderConfig.ExportMetrics {
					allProtosTotal.WithLabelValues(layerTypeStr).Inc()
				}

				// check if packet contains an unknown layer
				switch layer.LayerType() {
				case gopacket.LayerTypeZero: // not known to gopacket
					// increase counter
					unknownProtos.Inc(layerTypeStr)

					if c.config.DecoderConfig.ExportMetrics {
						unknownProtosTotal.WithLabelValues(layerTypeStr).Inc()
					}

					// write to unknown.pcap file
					if err = c.writePacketToUnknownPcap(pkt); err != nil {
						fmt.Println("failed to write packet to unknown.pcap file:", err)
					}

					// call custom decoders
					goto done
				case gopacket.LayerTypeDecodeFailure:
					// call custom decoders
					goto done
				}

				// pick decoders from the decoderMap by looking up the layer type
				if decoders, ok = c.goPacketDecoders[layer.LayerType()]; ok {
					for _, dec = range decoders {
						t := time.Now()
						err = dec.Decode(ctx, pkt, layer)
						duration := time.Since(t)
						gopacketDecoderTime.WithLabelValues(layerTypeStr).Set(float64(duration.Nanoseconds()))
						c.perfTracker.RecordGoPacketDecoder(layerTypeStr, duration)
						if err != nil {
							if c.config.DecoderConfig.ExportMetrics {
								decodingErrorsTotal.WithLabelValues(layerTypeStr, err.Error()).Inc()
							}

							if err = c.logPacketError(pkt, "GoPacketDecoder Error: "+layerTypeStr+": "+err.Error()); err != nil {
								fmt.Println("failed to log packet error:", err)
							}

							goto done
						}
					}
				} else { // no netcap decoder implemented

					// increment unknown layer type counter
					unknownProtos.Inc(layerTypeStr)
					if c.config.DecoderConfig.ExportMetrics {
						unknownProtosTotal.WithLabelValues(layerTypeStr).Inc()
					}

					// if its not a payload layer, write to unknown .pcap file
					if layer.LayerType() != gopacket.LayerTypePayload {
						if err = c.writePacketToUnknownPcap(pkt); err != nil {
							fmt.Println("failed to write packet to unknown.pcap file:", err)
						}
					}
				}
			} // END goPacket.Layers()

		done:
			// call custom decoders
			for _, customDec = range c.packetDecoders {
				t := time.Now()
				err = customDec.Decode(pkt, ctx)
				duration := time.Since(t)
				customDecoderTime.WithLabelValues(customDec.GetName()).Set(float64(duration.Nanoseconds()))
				c.perfTracker.RecordCustomDecoder(customDec.GetName(), duration)
				if err != nil {
					if c.config.DecoderConfig.ExportMetrics {
						decodingErrorsTotal.WithLabelValues(customDec.GetName(), err.Error()).Inc()
					}
					if err = c.logPacketError(pkt, "PacketDecoder Error: "+customDec.GetName()+": "+err.Error()); err != nil {
						fmt.Println("failed to log packet error:", err)
					}

					continue
				}
			}

			// Check for errors after decoding all layers
			// if an error has occurred while decoding the packet
			// it will be logged and written into the errors.pcap file
			if errLayer = pkt.ErrorLayer(); errLayer != nil {
				if err = c.logPacketError(pkt, errLayer.Error().Error()); err != nil {
					fmt.Println("failed to log packet error:", err)
				}

				if c.config.DecoderConfig.ExportMetrics {
					decodingErrorsTotal.WithLabelValues(errLayer.LayerType().String(), errLayer.Error().Error()).Inc()
				}
			}

			c.wg.Done()

			// Return PacketContext to pool for reuse
			packetContextPool.Put(ctx)

			// If using pool mode, dispose of the packet to return it to the pool
			// This must be done after all packet processing is complete
			if pooledPkt, ok := pkt.(gopacket.PooledPacket); ok {
				pooledPkt.Dispose()
			}

			continue
		}
	}()

	// return input channel
	return in
}

// spawn the configured number of workers.
func (c *Collector) initWorkers() []chan gopacket.Packet {

	// init worker slice
	workers := make([]chan gopacket.Packet, c.config.Workers)

	// create assemblers
	for i := range workers {
		a := reassembly.NewAssembler(tcp.GetStreamPool())

		// Configure stream reassembly limits from config
		if c.config.DecoderConfig.MaxStreamBytes > 0 {
			a.MaxStreamBytes = c.config.DecoderConfig.MaxStreamBytes
		}
		if c.config.DecoderConfig.MaxBufferedPagesPerConnection > 0 {
			a.MaxBufferedPagesPerConnection = c.config.DecoderConfig.MaxBufferedPagesPerConnection
		}
		if c.config.DecoderConfig.MaxBufferedPagesTotal > 0 {
			a.MaxBufferedPagesTotal = c.config.DecoderConfig.MaxBufferedPagesTotal
		}

		c.assemblers = append(c.assemblers, a)
		workers[i] = c.worker(a)
	}

	// update num worker count
	c.numWorkers = len(workers)

	return workers
}
