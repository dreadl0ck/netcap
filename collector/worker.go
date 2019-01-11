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

package collector

import (
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/google/gopacket"
)

// worker spawns a new worker goroutine
// and returns a channel for receiving input packets.
func (c *Collector) worker() chan gopacket.Packet {
	// init channel to receive input packets
	chanInput := make(chan gopacket.Packet, c.config.PacketBufferSize)

	// start worker
	go func() {
		for {
			select {
			case p := <-chanInput:

				// nil packet is used to exit goroutine
				if p == nil {
					return
				}

				// // experiment: only decode loaded layers
				// for lt, le := range encoder.LayerEncoders {

				// 	layer := p.Layer(lt)
				// 	if layer != nil {
				// 		c.allProtosAtomic.Inc(lt.String())
				// 		err := le.Encode(layer, p.Metadata().Timestamp)
				// 		if err != nil {
				// 			c.logPacketError(p, "Layer Encoder Error: "+lt.String()+": "+err.Error())
				// 			goto done
				// 		}
				// 	}
				// }

				// iterate over all layers
				for _, layer := range p.Layers() {
					c.allProtosAtomic.Inc(layer.LayerType().String())

					// check if packet contains an unknown layer
					switch layer.LayerType().String() {
					case "Unknown": // not known to gopacket
						c.unknownProtosAtomic.Inc(layer.LayerType().String())
						c.writePacketToUnknownPcap(p)
					case "DecodeFailure":
						goto done
					}

					// pick encoder from the encoderMap by looking up the layer type
					if d, ok := encoder.LayerEncoders[layer.LayerType()]; ok {
						err := d.Encode(layer, p.Metadata().Timestamp)
						if err != nil {
							c.logPacketError(p, "Layer Encoder Error: "+layer.LayerType().String()+": "+err.Error())
							goto done
						}
					} else { // no netcap encoder implemented
						c.unknownProtosAtomic.Inc(layer.LayerType().String())
						if layer.LayerType().String() != "Payload" {
							c.writePacketToUnknownPcap(p)
							goto done
						}
					}
				} // END packet.Layers()

			done:
				// call customencoders
				for _, dec := range encoder.CustomEncoders {
					err := dec.Encode(p)
					if err != nil {
						c.logPacketError(p, "CustomEncoder Error: "+dec.Name+": "+err.Error())
						continue
					}
				}

				// Check for errors after decoding all layers
				if errLayer := p.ErrorLayer(); errLayer != nil {
					c.logPacketError(p, errLayer.Error().Error())
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
func (c *Collector) initWorkers() []chan gopacket.Packet {
	workers := make([]chan gopacket.Packet, c.config.Workers)
	for i := range workers {
		workers[i] = c.worker()
	}
	return workers
}
