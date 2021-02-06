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
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"

	"github.com/dreadl0ck/gopacket"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

const (
	smtpAuthPlain   = "SMTP Auth Plain"
	smtpAuthLogin   = "SMTP Auth Login"
	smtpAuthCramMd5 = "SMTP Auth CRAM-MD5"

	serviceTelnet = "Telnet"
	serviceFTP    = "FTP"
	serviceHTTP   = "HTTP"

	// DecoderName is the name for the credentials decoder
	DecoderName = "Credentials"
)

// credentialHarvester is a function that takes the data of a bi-directional network stream over TCP
// as well as meta information and searches for credentials in the data
// on success a pointer to a types.Credential is returned, nil otherwise.
type credentialHarvester func(data []byte, ident string, ts time.Time) *types.Credentials

var (
	// useHarvesters controls whether the harvesters should be invoked or not.
	useHarvesters = false

	// harvesters to be ran against all seen bi-directional communication in a TCP session
	// new harvesters must be added here in order to get called.
	tcpConnectionHarvesters = []credentialHarvester{
		ftpHarvester,
		httpHarvester,
		smtpHarvester,
		telnetHarvester,
		imapHarvester,
	}

	// mapped port number to the harvester based on the IANA standards
	// used for the first guess which harvester to use.
	harvesterPortMapping = map[int]credentialHarvester{
		21:  ftpHarvester,
		80:  httpHarvester,
		587: smtpHarvester,
		465: smtpHarvester,
		25:  smtpHarvester,
		23:  telnetHarvester,
		143: imapHarvester,
	}

	// regular expressions for the harvesters.
	reFTP               = regexp.MustCompile(`220(?:.*?)\r\n(?:.*)\r?\n?(?:.*)\r?\n?USER\s(.*?)\r\n331(?:.*?)\r\nPASS\s(.*?)\r\n`)
	reHTTPBasic         = regexp.MustCompile(`(?:.*?)HTTP(?:[\s\S]*)(?:Authorization: Basic )(.*?)\r\n`)
	reHTTPDigest        = regexp.MustCompile(`(?:.*?)Authorization: Digest (.*?)\r\n`)
	reSMTPPlainSeparate = regexp.MustCompile(`(?:.*?)AUTH PLAIN\r\n334\r\n(.*?)\r\n(?:.*?)Authentication successful(?:.*?)$`)
	reSMTPPlainSingle   = regexp.MustCompile(`(?:.*?)AUTH PLAIN (.*?)\s\*\r\n235(?:.*?)`)
	reSMTPLogin         = regexp.MustCompile(`(?:.*?)AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n(.*?)\r\n334 UGFzc3dvcmQ6\r\n(.*?)\r\n235(?:.*?)`)
	reSMTPCramMd5       = regexp.MustCompile(`(?:.*?)AUTH CRAM-MD5(?:\r\n)334\s(.*?)(?:\r\n)(.*?)(\r\n)235(?:.*?)`)
	reTelnet            = regexp.MustCompile(`(?:.*?)login:(?:.*?)(\w*?)\r\n(?:.*?)\r\nPassword:\s(.*?)\r\n(?:.*?)`)
	reIMAPPlainSingle   = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\s(.*?)\s(.*?)\r\n(?:.*?)`)
	reIMATPlainSeparate = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\r\n(?:.*?)\sVXNlcm5hbWU6\r\n(.*?)\r\n(?:.*?)\sUGFzc3dvcmQ6\r\n(.*?)\r\n(?:.*?)`)
	reIMAPPlainAuth     = regexp.MustCompile(`(?:.*?)(?:AUTHENTICATE PLAIN|authenticate plain)\r\n(?:.*?)\r\n(.*?)\r\n(?:.*?)`)
	reIMAPPCramMd5      = regexp.MustCompile(`(?:.*?)AUTHENTICATE CRAM-MD5\r\n(?:.*?)\s(.*?)\r\n(.*?)\r\n(?:.*?)`)

	// credStore is used to deduplicate the credentials written to disk
	// it maps an identifier in the format: c.Service + c.User + c.Password
	// to the flow ident where the data was observed.
	credStore   = make(map[string]string)
	credStoreMu sync.Mutex
)

//goland:noinspection GoUnusedFunction
func harvesterDebug(ident string, data []byte, args ...interface{}) {
	fmt.Println(ident, "\n", hex.Dump(data), args)
}

// RunHarvesters will use the service probes to determine the service type based on the provided banner.
func RunHarvesters(banner []byte, transport gopacket.Flow, ident string, firstPacket time.Time) {
	// only use harvesters when credential audit record type is loaded
	// useHarvesters is set after the custom decoder initialization
	if !useHarvesters {
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
