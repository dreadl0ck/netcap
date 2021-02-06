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

// harvester for the FTP protocol.
func ftpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// harvesterDebug(ident, data, serviceFTP)

	matches := reFTP.FindSubmatch(data)
	if len(matches) > 1 {
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceFTP,
			Flow:      ident,
			User:      string(matches[1]),
			Password:  string(matches[2]),
		}
	}

	return nil
}
