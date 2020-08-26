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

package types

import "time"

var fieldsIPProfile = []string{
	"Addr",           // string
	"NumPackets",     // int64
	"Geolocation",    // string
	"DNSNames",       // []string
	"TimestampFirst", // int64
	"TimestampLast",  // int64
	"Applications",   // []string
	"Ja3",            // map[string]string
	"Protocols",      // map[string]*Protocol
	"Bytes",          // uint64
	"DstPorts",       // map[string]*Port
	"SrcPorts",       // map[string]*Port
	"SNIs",           // map[string]int64
}

// CSVHeader returns the CSV header for the audit record.
func (d *IPProfile) CSVHeader() []string {
	return filter(fieldsIPProfile)
}

// CSVRecord returns the CSV record for the audit record.
func (d *IPProfile) CSVRecord() []string {
	return filter([]string{
		d.Addr,
		formatInt64(d.NumPackets),
		d.Geolocation,
		// TODO: csv
		// d.DNSNames,
		// d.TimestampFirst,
		// d.TimestampLast,
		// d.Applications,
		// d.Ja3,
		// d.Protocols,
		// formatUint64(d.Bytes),
		// d.DstPorts,,
		// d.SrcPorts,
		// d.SNIs,
	})
}

// Time returns the timestamp associated with the audit record.
func (d *IPProfile) Time() int64 {
	return d.TimestampFirst
}

// JSON returns the JSON representation of the audit record.
func (d *IPProfile) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.TimestampFirst /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

// Inc increments the metrics for the audit record.
func (d *IPProfile) Inc() {}

// SetPacketContext sets the associated packet context for the audit record.
func (d *IPProfile) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (d *IPProfile) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (d *IPProfile) Dst() string {
	return ""
}
