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

	"github.com/gopacket/gopacket"

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
		// Original harvesters
		ftpHarvester,
		httpHarvester,
		smtpHarvester,
		telnetHarvester,
		imapHarvester,

		// Hash-based authentication
		ntlmsspHarvester,
		kerberosASReqHarvester, // Also works on TCP (Kerberos can use TCP with 4-byte length prefix)

		// New harvesters - Phase 1 (Quick Wins)
		httpNTLMHarvester, // HTTP NTLM with base64
		pop3Harvester,     // POP3 email
		redisHarvester,    // Redis AUTH
		snmpHarvester,     // SNMP community strings

		// New harvesters - Phase 2 (Database & Directory)
		ldapHarvester,         // LDAP Simple Bind
		postgresHarvester,     // PostgreSQL plaintext
		postgresHashHarvester, // PostgreSQL MD5 hashes
		mysqlHarvester,        // MySQL challenge-response

		// New harvesters - Phase 3 (Optional)
		vncHarvester,                      // VNC DES challenge-response
		mongodbHarvester,                  // MongoDB SCRAM-SHA
		mongodbChallengeResponseHarvester, // MongoDB wire protocol
		// creditCardHarvester,  // Credit card detection (disabled by default - enable via config)
	}

	// mapped port number to the harvester based on the IANA standards
	// used for the first guess which harvester to use.
	harvesterPortMapping = map[int]credentialHarvester{
		// Original mappings
		21:    ftpHarvester,
		23:    telnetHarvester,
		25:    smtpHarvester,
		80:    httpHarvester,
		110:   pop3Harvester, // POP3
		143:   imapHarvester,
		161:   snmpHarvester,     // SNMP
		162:   snmpHarvester,     // SNMP Trap
		389:   ldapHarvester,     // LDAP
		445:   ntlmsspHarvester,  // SMB
		465:   smtpHarvester,     // SMTP over SSL
		587:   smtpHarvester,     // SMTP submission
		636:   ldapHarvester,     // LDAPS
		995:   pop3Harvester,     // POP3 over SSL
		3306:  mysqlHarvester,    // MySQL/MariaDB
		5432:  postgresHarvester, // PostgreSQL
		5900:  vncHarvester,      // VNC (5900-5909 for displays 0-9)
		5901:  vncHarvester,
		5902:  vncHarvester,
		5903:  vncHarvester,
		5904:  vncHarvester,
		5905:  vncHarvester,
		5906:  vncHarvester,
		5907:  vncHarvester,
		5908:  vncHarvester,
		5909:  vncHarvester,
		6379:  redisHarvester,   // Redis
		8080:  httpHarvester,    // HTTP alternate / dev servers etc
		3000:  httpHarvester,    // HTTP alternate / dev servers etc
		9090:  httpHarvester,    // HTTP alternate / dev servers etc
		8888:  httpHarvester,    // HTTP alternate / dev servers etc
		27017: mongodbHarvester, // MongoDB
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

// ResetCredStore clears the credentials deduplication store
// This should be called when resetting state between processing different files
func ResetCredStore() {
	credStoreMu.Lock()
	credStore = make(map[string]string)
	credStoreMu.Unlock()
}

//goland:noinspection GoUnusedFunction
func harvesterDebug(ident string, data []byte, args ...interface{}) {
	fmt.Println(ident, "\n", hex.Dump(data), args)
}

// RunHarvesters will use the service probes to determine the service type based on the provided banner.
// The banner parameter contains at most HarvesterBannerSize bytes from the stream conversation,
// which is pre-truncated to prevent performance issues when processing large data streams
// (e.g., file transfers, database dumps, video streaming, etc.).
func RunHarvesters(banner []byte, transport gopacket.Flow, ident string, firstPacket time.Time) {
	// only use harvesters when credential audit record type is loaded
	// useHarvesters is set after the custom decoder initialization
	if !useHarvesters {
		return
	}

	// Additional safety check: ensure we don't process more than the configured limit
	// This should already be enforced by createBannerFromConversation, but we add
	// a safeguard here in case the banner is created elsewhere
	if len(banner) > decoderconfig.Instance.HarvesterBannerSize {
		banner = banner[:decoderconfig.Instance.HarvesterBannerSize]
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
}
