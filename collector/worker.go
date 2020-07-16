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
	"fmt"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/encoder"
)

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func (c *Collector) worker(assembler *reassembly.Assembler) chan *packet {

	// init channel to receive input packets
	chanInput := make(chan *packet, c.config.PacketBufferSize)

	// start worker
	go func() {
		for {
			select {
			case packet := <-chanInput:

				// nil packet is used to exit goroutine
				if packet == nil {
					return
				}

				// create a new gopacket
				// base layer is by default Ethernet
				p := gopacket.NewPacket(packet.data, c.config.BaseLayer, c.config.DecodeOptions)
				p.Metadata().Timestamp = packet.ci.Timestamp
				p.Metadata().CaptureInfo = packet.ci
				p.Metadata().Length = packet.ci.Length
				p.Metadata().CaptureLength = packet.ci.CaptureLength

				// pass packet to reassembly
				if c.config.ReassembleConnections {
					encoder.ReassemblePacket(p, assembler)
				}

				// create context for packet
				var ctx = &types.PacketContext{}
				if encoder.AddContext {
					var (
						netLayer       = p.NetworkLayer()
						transportLayer = p.TransportLayer()
					)
					if netLayer != nil {
						ctx.SrcIP = netLayer.NetworkFlow().Src().String()
						ctx.DstIP = netLayer.NetworkFlow().Dst().String()
					}
					if transportLayer != nil {
						ctx.SrcPort = transportLayer.TransportFlow().Src().String()
						ctx.DstPort = transportLayer.TransportFlow().Dst().String()
					}
				}

				// iterate over all layers
				for _, layer := range p.Layers() {

					// increment counter for layer type
					c.allProtosAtomic.Inc(layer.LayerType().String())

					if c.config.EncoderConfig.Export {
						allProtosTotal.WithLabelValues(layer.LayerType().String()).Inc()
					}

					// check if packet contains an unknown layer
					switch layer.LayerType() {
					case gopacket.LayerTypeZero: // not known to gopacket

						// increase counter
						c.unknownProtosAtomic.Inc(layer.LayerType().String())
						if c.config.EncoderConfig.Export {
							unknownProtosTotal.WithLabelValues(layer.LayerType().String()).Inc()
						}

						// write to unknown.pcap file
						if err := c.writePacketToUnknownPcap(p); err != nil {
							fmt.Println("failed to write packet to unknown.pcap file:", err)
						}

						// call custom decoders
						goto done
					case gopacket.LayerTypeDecodeFailure:
						// call custom decoders
						goto done
					}

					// pick encoders from the encoderMap by looking up the layer type
					if encoders, ok := encoder.LayerEncoders[layer.LayerType()]; ok {

						for _, e := range encoders {
							err := e.Encode(ctx, p, layer)
							if err != nil {
								if err := c.logPacketError(p, "Layer Encoder Error: "+layer.LayerType().String()+": "+err.Error()); err != nil {
									fmt.Println("failed to log packet error:", err)
								}
								if c.config.EncoderConfig.Export {
									decodingErrorsTotal.WithLabelValues(layer.LayerType().String(), err.Error()).Inc()
								}
								goto done
							}
						}
					} else { // no netcap encoder implemented

						// increment unknown layer type counter
						c.unknownProtosAtomic.Inc(layer.LayerType().String())
						if c.config.EncoderConfig.Export {
							unknownProtosTotal.WithLabelValues(layer.LayerType().String()).Inc()
						}

						// if its not a payload layer, write to unknown .pcap file
						if layer.LayerType() != gopacket.LayerTypePayload {
							if err := c.writePacketToUnknownPcap(p); err != nil {
								fmt.Println("failed to write packet to unknown.pcap file:", err)
							}
						}
					}
				} // END packet.Layers()

			done:
				// call custom encoders
				for _, e := range encoder.CustomEncoders {
					err := e.Encode(p)
					if err != nil {
						if err := c.logPacketError(p, "CustomEncoder Error: "+e.Name+": "+err.Error()); err != nil {
							fmt.Println("failed to log packet error:", err)
						}
						if c.config.EncoderConfig.Export {
							decodingErrorsTotal.WithLabelValues(e.Name, err.Error()).Inc()
						}
						continue
					}
				}

				// Check for errors after decoding all layers
				// if an error has occurred while decoding the packet
				// it will be logged and written into the errors.pcap file
				if errLayer := p.ErrorLayer(); errLayer != nil {
					if err := c.logPacketError(p, errLayer.Error().Error()); err != nil {
						fmt.Println("failed to log packet error:", err)
					}
					if c.config.EncoderConfig.Export {
						decodingErrorsTotal.WithLabelValues(errLayer.LayerType().String(), errLayer.Error().Error()).Inc()
					}
				}
			}

			c.wg.Done()
			continue
		}

	}()

	// return input channel
	return chanInput
}

// spawn the configured number of workers
func (c *Collector) initWorkers() []chan *packet {
	workers := make([]chan *packet, c.config.Workers)
	for i := range workers {
		a := reassembly.NewAssembler(encoder.StreamPool)
		c.assemblers = append(c.assemblers, a)
		workers[i] = c.worker(a)
	}
	c.numWorkers = len(workers)
	return workers
}
