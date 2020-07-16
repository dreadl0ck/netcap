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

package encoder

import (
	"bytes"
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"
)

/*
 * TCP
 */

type tcpReader struct {
	parent *tcpConnection
}

func (h *tcpReader) Decode(c2s, s2c Stream) {

}

func getServiceName(data []byte, flow gopacket.Flow) string {

	var (
		dstPort, _ = strconv.Atoi(flow.Dst().String())
		s          = resolvers.LookupServiceByPort(dstPort, "tcp")
	)
	if s != "" {
		return s
	}

	// what about the source port?
	srcPort, _ := strconv.Atoi(flow.Src().String())
	s = resolvers.LookupServiceByPort(srcPort, "tcp")
	if s != "" {
		return s
	}

	// still no clue? lets check if its ascii
	if utils.IsASCII(data) {
		return "ascii"
	}

	return "unknown"
}

func runHarvesters(raw []byte, transport gopacket.Flow, ident string, firstPacket time.Time) []byte {

	// only use harvesters when credential audit record type is loaded
	// useHarvesters is set after the custom encoder initialization
	if !useHarvesters {
		return raw
	}

	var (
		banner = make([]byte, 0, c.HarvesterBannerSize)
		found  bool
		tried  *CredentialHarvester
	)

	// copy c.HarvesterBannerSize number of bytes from the raw conversation
	// to use for the credential harvesters
	for i, b := range raw {
		if i >= c.HarvesterBannerSize {
			break
		}
		banner = append(banner, b)
	}

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
		if creds := ch(banner, ident, firstPacket); creds != nil {

			// write audit record
			writeCredentials(creds)

			// we found a match and will stop processing
			if c.StopAfterHarvesterMatch {
				found = true
			}
		}
		// save the address of the harvester function
		// we dont need to run it again
		tried = &ch
	}

	if ch, ok := harvesterPortMapping[srcPort]; ok {
		if creds := ch(banner, ident, firstPacket); creds != nil {

			// write audit record
			writeCredentials(creds)

			// we found a match and will stop processing
			if c.StopAfterHarvesterMatch {
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
				if creds := ch(banner, ident, firstPacket); creds != nil {

					// write audit record
					writeCredentials(creds)

					// stop after a match for now
					if c.StopAfterHarvesterMatch {
						break
					}
				}
			}
		}
	}

	return banner
}

func saveConnection(raw []byte, colored []byte, ident string, firstPacket time.Time, transport gopacket.Flow) error {

	// prevent processing zero bytes
	if len(raw) == 0 {
		return nil
	}

	banner := runHarvesters(raw, transport, ident, firstPacket)

	if !c.SaveConns {
		return nil
	}

	//fmt.Println("save conn", ident, len(raw), len(colored))
	//fmt.Println(string(colored))

	var (
		typ = getServiceName(banner, transport)

		// path for storing the data
		root = filepath.Join(c.Out, "tcpConnections", typ)

		// file basename
		base = filepath.Clean(path.Base(ident)) + ".bin"
	)

	// make sure root path exists
	os.MkdirAll(root, defaultDirectoryPermission)
	base = path.Join(root, base)

	utils.ReassemblyLog.Println("saveConnection", base)

	statsMutex.Lock()
	reassemblyStats.savedTCPConnections++
	statsMutex.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0700)
	if err != nil {
		logReassemblyError("TCP conn create", "Cannot create %s: %s\n", base, err)
		return err
	}

	// do not colorize the data written to disk if its just a single keepalive byte
	if len(raw) == 1 {
		colored = raw
	}

	// save the colored version
	// assign a new buffer
	r := bytes.NewBuffer(colored)
	w, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError("TCP stream", "%s: failed to save TCP conn %s (l:%d): %s\n", ident, base, w, err)
	} else {
		logReassemblyInfo("%s: Saved TCP conn %s (l:%d)\n", ident, base, w)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("TCP conn", "%s: failed to close TCP conn file %s (l:%d): %s\n", ident, base, w, err)
	}

	return nil
}

func tcpDebug(args ...interface{}) {
	if c.TCPDebug {
		utils.DebugLog.Println(args...)
	}
}
