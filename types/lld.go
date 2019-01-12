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
)

func (l LinkLayerDiscovery) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"ChassisID", // *LLDPChassisID
		"PortID",    // *LLDPPortID
		"TTL",       // int32
		"Values",    // []*LinkLayerDiscoveryValue
	})
}

func (l LinkLayerDiscovery) CSVRecord() []string {
	values := make([]string, len(l.Values))
	for i, v := range l.Values {
		values[i] = v.ToString()
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		l.ChassisID.ToString(), // *LLDPChassisID
		l.PortID.ToString(),    // *LLDPPortID
		formatInt32(l.TTL),     // int32
		join(values...),        // []*LinkLayerDiscoveryValue
	})
}

func (l LinkLayerDiscovery) NetcapTimestamp() string {
	return l.Timestamp
}

func (l LLDPChassisID) ToString() string {
	return join(formatInt32(l.Subtype), hex.EncodeToString(l.ID))
}

func (l LLDPPortID) ToString() string {
	return join(formatInt32(l.Subtype), hex.EncodeToString(l.ID))
}
