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
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// harvester for the HTTP protocol.
func httpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	var (
		matchesBasic  = reHTTPBasic.FindSubmatch(data)
		matchesDigest = reHTTPDigest.FindSubmatch(data)
		username      string
		password      string
	)

	if len(matchesBasic) > 1 {
		extractedData, err := base64.StdEncoding.DecodeString(string(matchesBasic[1]))
		if err != nil {
			fmt.Println("captured HTTP Basic Auth credentials, but could not decode them")
		}
		creds := strings.Split(string(extractedData), ":")
		username = creds[0]
		password = creds[1]
	}

	if len(matchesDigest) > 1 {
		username = string(matchesDigest[1])
		password = "" // This doesn't retrieve creds per se. It retrieves the info needed to crack them
	}

	if len(username) > 1 {
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   "HTTP Basic Auth",
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil
}
