/*
 * JA3 - TLS Client Hello Hash
 * Copyright (c) 2017, Salesforce.com, Inc.
 * this code was created by Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ja3

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Record contains all information for a calculated JA3
type Record struct {
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
	JA3             string `json:"ja3"`
	JA3Digest       string `json:"ja3_digest"`
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port"`
	Timestamp       string `json:"timestamp"`
}

// ReadFileJSON reads the PCAP file at the given path
// and prints out all packets containing JA3 digests fromatted as JSON to the supplied io.Writer
func ReadFileJSON(file string, out io.Writer) {

	r, f, err := openPcap(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var records []*Record

	for {
		// read packet data
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		var (
			// create gopacket
			p = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)

			// get JA3 if possible
			bare = BarePacket(p)
		)

		// check if we got a result
		if len(bare) > 0 {

			var (
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// stop if either network or transport layer is nil
			if tl == nil || nl == nil {
				fmt.Println("error: ", nl, tl, p.Dump())
				continue
			}

			// convert ports to integers, ignore errors
			srcPort, _ := strconv.Atoi(tl.TransportFlow().Src().String())
			dstPort, _ := strconv.Atoi(tl.TransportFlow().Dst().String())

			// append record and populate all fields
			records = append(records, &Record{
				DestinationIP:   nl.NetworkFlow().Dst().String(),
				DestinationPort: dstPort,
				JA3:             string(bare),
				JA3Digest:       BareToDigestHex(bare),
				SourceIP:        nl.NetworkFlow().Src().String(),
				SourcePort:      srcPort,
				Timestamp:       timeToString(ci.Timestamp),
			})
		}
	}

	// make it pretty please
	b, err := json.MarshalIndent(records, "", "    ")
	if err != nil {
		panic(err)
	}

	// write to output io.Writer
	_, err = out.Write(b)
	if err != nil {
		panic(err)
	}

	if Debug {
		fmt.Println(len(records), "fingeprints.")
	}
}

// convert a time.Time to a string timestamp in the format seconds.microseconds
func timeToString(t time.Time) string {
	micro := fmt.Sprintf("%06d", t.Nanosecond()/1000)
	return strconv.FormatInt(t.Unix(), 10) + "." + micro
}
