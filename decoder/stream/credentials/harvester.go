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

package credentials

import (
	"fmt"
	"strconv"
	"time"

	"github.com/dreadl0ck/gopacket"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

// RunHarvesters will use the service probes to determine the service type based on the provided banner.
func RunHarvesters(banner []byte, transport gopacket.Flow, ident string, firstPacket time.Time) {
	// only use harvesters when credential audit record type is loaded
	// useHarvesters is set after the custom decoder initialization
	if !UseHarvesters {
		return
	}

	var (
		found bool
		tried *credentialHarvester
	)

	// convert service port to integer
	dstPort, err := strconv.Atoi(transport.Dst().String())
	if err != nil {
		fmt.Println(err)
	}

	srcPort, err := strconv.Atoi(transport.Src().String())
	if err != nil {
		fmt.Println(err)
	}

	// check if its a well known port and use the harvester for that one
	if ch, ok := harvesterPortMapping[dstPort]; ok {
		if creds := ch(banner, ident, firstPacket); creds != nil { // write audit record
			WriteCredentials(creds)

			// we found a match and will stop processing
			if decoderconfig.Instance.StopAfterHarvesterMatch {
				found = true
			}
		}
		// save the address of the harvester function
		// we dont need to run it again
		tried = &ch
	}

	if ch, ok := harvesterPortMapping[srcPort]; ok {
		if creds := ch(banner, ident, firstPacket); creds != nil { // write audit record
			WriteCredentials(creds)

			// we found a match and will stop processing
			if decoderconfig.Instance.StopAfterHarvesterMatch {
				found = true
			}
		}
		// save the address of the harvester function
		// we dont need to run it again
		tried = &ch
	}

	// if we dont have a match yet, match against all available harvesters
	if !found {
		// iterate over all harvesters
		for _, ch := range tcpConnectionHarvesters {
			// if the port based first guess has not been found, do not run this harvester again
			if &ch != tried {
				// execute harvester
				if creds := ch(banner, ident, firstPacket); creds != nil { // write audit record
					WriteCredentials(creds)

					// stop after a match if configured
					if decoderconfig.Instance.StopAfterHarvesterMatch {
						break
					}
				}
			}
		}
	}

	return
}
