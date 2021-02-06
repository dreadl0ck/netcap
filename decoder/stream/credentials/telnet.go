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
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// harvester for telnet traffic.
func telnetHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	matches := reTelnet.FindSubmatch(data)
	if len(matches) > 1 {
		var username string
		for i, letter := range string(matches[1]) {
			if i%2 == 0 {
				username = username + string(letter)
			}
		}
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceTelnet,
			Flow:      ident,
			User:      username,
			Password:  string(matches[2]),
		}
	}
	return nil
}
