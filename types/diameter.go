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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldMessageLen    = "MessageLen"
	fieldCommandCode   = "CommandCode"
	fieldApplicationID = "ApplicationID"
	fieldHopByHopID    = "HopByHopID"
	fieldEndToEndID    = "EndToEndID"
	fieldAVPs          = "AVPs"
)

var fieldsDiameter = []string{
	fieldTimestamp,
	fieldVersion,       // uint32
	fieldFlags,         // uint32
	fieldMessageLen,    // uint32
	fieldCommandCode,   // uint32
	fieldApplicationID, // uint32
	fieldHopByHopID,    // uint32
	fieldEndToEndID,    // uint32
	//fieldAVPs,          // []*AVP
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (d *Diameter) CSVHeader() []string {
	return filter(fieldsDiameter)
}

// CSVRecord returns the CSV record for the audit record.
func (d *Diameter) CSVRecord() []string {
	var avps []string

	for _, a := range d.AVPs {
		avps = append(avps, a.String())
	}

	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatUint32(d.Version),       //       uint32
		formatUint32(d.Flags),         //         uint32
		formatUint32(d.MessageLen),    //    uint32
		formatUint32(d.CommandCode),   //   uint32
		formatUint32(d.ApplicationID), // uint32
		formatUint32(d.HopByHopID),    //    uint32
		formatUint32(d.EndToEndID),    //    uint32
		//join(avps...),                 //     []*AVP
		d.SrcIP,
		d.DstIP,
		formatInt32(d.SrcPort),
		formatInt32(d.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (d *Diameter) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *Diameter) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var diameterMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Diameter.String()),
		Help: Type_NC_Diameter.String() + " audit records",
	},
	fieldsDiameter[1:],
)

// Inc increments the metrics for the audit record.
func (d *Diameter) Inc() {
	diameterMetric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *Diameter) SetPacketContext(ctx *PacketContext) {
	d.SrcIP = ctx.SrcIP
	d.DstIP = ctx.DstIP
	d.SrcPort = ctx.SrcPort
	d.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (d *Diameter) Src() string {
	return d.SrcIP
}

// Dst returns the destination address of the audit record.
func (d *Diameter) Dst() string {
	return d.DstIP
}

var diameterEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *Diameter) Encode() []string {
	return filter([]string{
		diameterEncoder.Int64(fieldTimestamp, d.Timestamp),
		diameterEncoder.Uint32(fieldVersion, d.Version),             // uint32
		diameterEncoder.Uint32(fieldFlags, d.Flags),                 // uint32
		diameterEncoder.Uint32(fieldMessageLen, d.MessageLen),       // uint32
		diameterEncoder.Uint32(fieldCommandCode, d.CommandCode),     // uint32
		diameterEncoder.Uint32(fieldApplicationID, d.ApplicationID), // uint32
		diameterEncoder.Uint32(fieldHopByHopID, d.HopByHopID),       // uint32
		diameterEncoder.Uint32(fieldEndToEndID, d.EndToEndID),       // uint32
		// TODO: flatten
		//join(avps...),                 // []*AVP
		diameterEncoder.String(fieldSrcIP, d.SrcIP),
		diameterEncoder.String(fieldDstIP, d.DstIP),
		diameterEncoder.Int32(fieldSrcPort, d.SrcPort),
		diameterEncoder.Int32(fieldDstPort, d.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *Diameter) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *Diameter) NetcapType() Type {
	return Type_NC_Diameter
}
