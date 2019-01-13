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

package types

import (
	"encoding/hex"
	"strconv"
)

func (u UDP) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"SrcPort",
		"DstPort",
		"Length",
		"Checksum",
		"PayloadEntropy",
		"PayloadSize",
		"Payload",
	})
}

func (u UDP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(u.Timestamp),                      // string
		formatInt32(u.SrcPort),                            // int32
		formatInt32(u.DstPort),                            // int32
		formatInt32(u.Length),                             // int32
		formatInt32(u.Checksum),                           // int32
		strconv.FormatFloat(u.PayloadEntropy, 'f', 8, 64), // float64
		formatInt32(u.PayloadSize),                        // int32
		hex.EncodeToString(u.Payload),
	})
}

func (f UDP) NetcapTimestamp() string {
	return f.Timestamp
}
