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

import (
	"github.com/dreadl0ck/netcap/encoder"
	"time"
)

const (
	fieldAddr         = "Addr"
	fieldGeolocation  = "Geolocation"
	fieldDNSNames     = "DNSNames"
	fieldApplications = "Applications"
	fieldJa3          = "Ja3"
	fieldProtocols    = "Protocols"
	fieldDstPorts     = "DstPorts"
	fieldSrcPorts     = "SrcPorts"
	fieldSNIs         = "SNIs"
)

var fieldsIPProfile = []string{
	fieldAddr,           // string
	fieldNumPackets,     // int64
	fieldGeolocation,    // string
	fieldDNSNames,       // []string
	fieldTimestampFirst, // int64
	fieldTimestampLast,  // int64
	fieldApplications,   // []string
	//fieldJa3,            // map[string]string
	//fieldProtocols,      // map[string]*Protocol
	fieldBytes, // uint64
	//fieldDstPorts,       // map[string]*Port
	//fieldSrcPorts,       // map[string]*Port
	//fieldSNIs,           // map[string]int64
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
		join(d.DNSNames...),
		formatInt64(d.TimestampFirst),
		formatInt64(d.TimestampLast),
		join(d.Applications...),
		// d.Ja3,
		// d.Protocols,
		formatUint64(d.Bytes),
		// d.DstPorts,
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
	d.TimestampLast /= int64(time.Millisecond)

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

var ipProfileEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *IPProfile) Encode() []string {
	return filter([]string{
		ipProfileEncoder.String(fieldAddr, d.Addr),
		ipProfileEncoder.Int64(fieldNumPackets, d.NumPackets),
		ipProfileEncoder.String(fieldGeolocation, d.Geolocation),
		ipProfileEncoder.String(fieldDNSNames, join(d.DNSNames...)),
		ipProfileEncoder.Int64(fieldTimestampFirst, d.TimestampFirst),
		ipProfileEncoder.Int64(fieldTimestampLast, d.TimestampLast),
		ipProfileEncoder.String(fieldApplications, join(d.Applications...)),
		ipProfileEncoder.Uint64(fieldBytes, d.Bytes),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *IPProfile) Analyze() {}

// NetcapType returns the type of the current audit record
func (d *IPProfile) NetcapType() Type {
	return Type_NC_IPProfile
}
