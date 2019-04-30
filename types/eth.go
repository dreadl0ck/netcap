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

func (e Ethernet) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"SrcMAC",         // string
		"DstMAC",         // string
		"EthernetType",   // int32
		"PayloadEntropy", // float64
		"PayloadSize",    // int32
	})
}
func (e Ethernet) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(e.Timestamp),
		e.SrcMAC,                        // string
		e.DstMAC,                        // string
		formatInt32(e.EthernetType),     // int32
		formatFloat64(e.PayloadEntropy), // float64
		formatInt32(e.PayloadSize),      // int32
	})
}

func (e Ethernet) NetcapTimestamp() string {
	return e.Timestamp
}

func (a Ethernet) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}
