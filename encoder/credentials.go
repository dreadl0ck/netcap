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
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"regexp"
	"time"
)

// CredentialHarvester is a function that takes the data of a bi-directional network stream over TCP
// as well as meta information and searches for credentials in the data
// on success a pointer to a types.Credential is returned, nil otherwise
type CredentialHarvester func(data []byte, ident string, ts time.Time) *types.Credentials

// harvesters to be ran against all seen bi-directional communication in a TCP session
var tcpConnectionHarvesters = []CredentialHarvester{
	ftpHarvester,
}

// FTP protocol
var ftpCredentialsRegex, errFtpRegex = regexp.Compile("220(.*)\\r\\nUSER\\s(.*)\\r\\n331(.*)\\r\\nPASS\\s(.*)\\r\\n")
func ftpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {

	if m := ftpCredentialsRegex.FindStringSubmatch(string(data)); m != nil {

		if len(m) <= 4 {
			fmt.Println("FTP credential harvester: not enough groups from regex", m)
			return nil
		}

		return &types.Credentials{
			Timestamp: ts.String(),
			Service:   "FTP",
			Flow:      ident,
			User:      m[2],
			Password:  m[4],
		}
	}

	return nil
}

var credentialsEncoder = CreateCustomEncoder(types.Type_NC_Credentials, "Credentials", func(d *CustomEncoder) error {

	// credential encoder init: check errors from compiling harvester regexes here
	if errFtpRegex != nil {
		return errFtpRegex
	}

	return nil
}, func(p gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {
	return nil
})
