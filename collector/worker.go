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

package collector

import (
	"encoding/binary"
	"fmt"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func (c *Collector) worker(assembler *reassembly.Assembler) chan *packet {
	var (
		in       = make(chan *packet, c.config.PacketBufferSize)
		pkt      *packet
		goPacket gopacket.Packet

		errLayer gopacket.ErrorLayer
		err      error

		decoders  []*decoder.GoPacketDecoder
		dec       *decoder.GoPacketDecoder
		customDec decoder.CustomDecoderAPI
		ok        bool

		netLayer       gopacket.NetworkLayer
		transportLayer gopacket.TransportLayer
		layer          gopacket.Layer
	)

	// start worker
	go func() {
		for pkt = range in {
			// nil packet is used to exit goroutine
			if pkt == nil {
				return
			}

			// create a new gopacket
			// base layer is by default Ethernet
			goPacket = gopacket.NewPacket(pkt.data, c.config.BaseLayer, c.config.DecodeOptions)
			goPacket.Metadata().Timestamp = pkt.ci.Timestamp
			goPacket.Metadata().CaptureInfo = pkt.ci
			goPacket.Metadata().Length = pkt.ci.Length
			goPacket.Metadata().CaptureLength = pkt.ci.CaptureLength

			// pass packet to reassembly
			if c.config.ReassembleConnections {
				decoder.ReassemblePacket(goPacket, assembler)
			}

			// create context for packet
			ctx := &types.PacketContext{}

			if c.config.DecoderConfig.AddContext {
				netLayer = goPacket.NetworkLayer()
				transportLayer = goPacket.TransportLayer()

				if netLayer != nil {
					ctx.SrcIP = netLayer.NetworkFlow().Src().String()
					ctx.DstIP = netLayer.NetworkFlow().Dst().String()
				}

				if transportLayer != nil {
					ctx.SrcPort = int32(binary.BigEndian.Uint16(transportLayer.TransportFlow().Src().Raw()))
					ctx.DstPort = int32(binary.BigEndian.Uint16(transportLayer.TransportFlow().Dst().Raw()))
				}
			}

			// iterate over all layers
			for _, layer = range goPacket.Layers() {
				// increment counter for layer type
				c.allProtosAtomic.Inc(layer.LayerType().String())

				if c.config.DecoderConfig.ExportMetrics {
					allProtosTotal.WithLabelValues(layer.LayerType().String()).Inc()
				}

				// check if packet contains an unknown layer
				switch layer.LayerType() {
				case gopacket.LayerTypeZero: // not known to gopacket
					// increase counter
					c.unknownProtosAtomic.Inc(layer.LayerType().String())

					if c.config.DecoderConfig.ExportMetrics {
						unknownProtosTotal.WithLabelValues(layer.LayerType().String()).Inc()
					}

					// write to unknown.pcap file
					if err = c.writePacketToUnknownPcap(goPacket); err != nil {
						fmt.Println("failed to write packet to unknown.pcap file:", err)
					}

					// call custom decoders
					goto done
				case gopacket.LayerTypeDecodeFailure:
					// call custom decoders
					goto done
				}

				// pick decoders from the encoderMap by looking up the layer type
				if decoders, ok = c.goPacketDecoders[layer.LayerType()]; ok {
					for _, dec = range decoders {
						err = dec.Decode(ctx, goPacket, layer)
						if err != nil {
							if c.config.DecoderConfig.ExportMetrics {
								decodingErrorsTotal.WithLabelValues(layer.LayerType().String(), err.Error()).Inc()
							}

							if err = c.logPacketError(goPacket, "GoPacketDecoder Error: "+layer.LayerType().String()+": "+err.Error()); err != nil {
								fmt.Println("failed to log packet error:", err)
							}

							goto done
						}
					}
				} else { // no netcap encoder implemented
					// increment unknown layer type counter
					c.unknownProtosAtomic.Inc(layer.LayerType().String())
					if c.config.DecoderConfig.ExportMetrics {
						unknownProtosTotal.WithLabelValues(layer.LayerType().String()).Inc()
					}

					// if its not a payload layer, write to unknown .pcap file
					if layer.LayerType() != gopacket.LayerTypePayload {
						if err = c.writePacketToUnknownPcap(goPacket); err != nil {
							fmt.Println("failed to write packet to unknown.pcap file:", err)
						}
					}
				}
			} // END goPacket.Layers()

		done:
			// call custom decoders
			for _, customDec = range c.customDecoders {
				err = customDec.Decode(goPacket)
				if err != nil {
					if c.config.DecoderConfig.ExportMetrics {
						decodingErrorsTotal.WithLabelValues(customDec.GetName(), err.Error()).Inc()
					}
					if err = c.logPacketError(goPacket, "CustomDecoder Error: "+customDec.GetName()+": "+err.Error()); err != nil {
						fmt.Println("failed to log packet error:", err)
					}

					continue
				}
			}

			// Check for errors after decoding all layers
			// if an error has occurred while decoding the packet
			// it will be logged and written into the errors.pcap file
			if errLayer = goPacket.ErrorLayer(); errLayer != nil {
				if err = c.logPacketError(goPacket, errLayer.Error().Error()); err != nil {
					fmt.Println("failed to log packet error:", err)
				}

				if c.config.DecoderConfig.ExportMetrics {
					decodingErrorsTotal.WithLabelValues(errLayer.LayerType().String(), errLayer.Error().Error()).Inc()
				}
			}

			c.wg.Done()

			continue
		}
	}()

	// return input channel
	return in
}

// spawn the configured number of workers.
func (c *Collector) initWorkers() []chan *packet {
	workers := make([]chan *packet, c.config.Workers)
	for i := range workers {
		a := reassembly.NewAssembler(decoder.GetStreamPool())
		c.assemblers = append(c.assemblers, a)
		workers[i] = c.worker(a)
	}

	c.numWorkers = len(workers)

	return workers
}
