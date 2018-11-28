/*
 * NETCAP - Network Capture Toolkit
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
	"strconv"
)

func (d Dot1Q) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Priority",       //  int32
		"DropEligible",   //  bool
		"VLANIdentifier", //  int32
		"Type",           //  int32
	})
}

func (d Dot1Q) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatInt32(d.Priority),            //  int32
		strconv.FormatBool(d.DropEligible), //  bool
		formatInt32(d.VLANIdentifier),      //  int32
		formatInt32(d.Type),                //  int32
	})
}

func (d Dot1Q) NetcapTimestamp() string {
	return d.Timestamp
}
