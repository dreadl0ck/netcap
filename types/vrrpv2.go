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
	fieldVirtualRtrID = "VirtualRtrID"
	fieldCountIPAddr  = "CountIPAddr"
	fieldAuthType     = "AuthType"
	fieldAdverInt     = "AdverInt"
	fieldIPAddresses  = "IPAddresses"
)

var fieldsVRRPv2 = []string{
	fieldTimestamp,
	fieldVersion,      // int32
	fieldType,         // int32
	fieldVirtualRtrID, // int32
	fieldPriority,     // int32
	fieldCountIPAddr,  // int32
	fieldAuthType,     // int32
	fieldAdverInt,     // int32
	fieldChecksum,     // int32
	fieldIPAddresses,  // []string
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *VRRPv2) CSVHeader() []string {
	return filter(fieldsVRRPv2)
}

// CSVRecord returns the CSV record for the audit record.
func (a *VRRPv2) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),      // int32
		formatInt32(a.Type),         // int32
		formatInt32(a.VirtualRtrID), // int32
		formatInt32(a.Priority),     // int32
		formatInt32(a.CountIPAddr),  // int32
		formatInt32(a.AuthType),     // int32
		formatInt32(a.AdverInt),     // int32
		formatInt32(a.Checksum),     // int32
		join(a.IPAddress...),        // []string
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *VRRPv2) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *VRRPv2) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var vrrp2Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_VRRPv2.String()),
		Help: Type_NC_VRRPv2.String() + " audit records",
	},
	fieldsVRRPv2[1:],
)

// Inc increments the metrics for the audit record.
func (a *VRRPv2) Inc() {
	vrrp2Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *VRRPv2) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *VRRPv2) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *VRRPv2) Dst() string {
	return a.DstIP
}

var vrrpv2Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *VRRPv2) Encode() []string {
	return filter([]string{
		vrrpv2Encoder.Int64(fieldTimestamp, a.Timestamp),
		vrrpv2Encoder.Int32(fieldVersion, a.Version),                 // int32
		vrrpv2Encoder.Int32(fieldType, a.Type),                       // int32
		vrrpv2Encoder.Int32(fieldVirtualRtrID, a.VirtualRtrID),       // int32
		vrrpv2Encoder.Int32(fieldPriority, a.Priority),               // int32
		vrrpv2Encoder.Int32(fieldCountIPAddr, a.CountIPAddr),         // int32
		vrrpv2Encoder.Int32(fieldAuthType, a.AuthType),               // int32
		vrrpv2Encoder.Int32(fieldAdverInt, a.AdverInt),               // int32
		vrrpv2Encoder.Int32(fieldChecksum, a.Checksum),               // int32
		vrrpv2Encoder.String(fieldIPAddresses, join(a.IPAddress...)), // []string
		vrrpv2Encoder.String(fieldSrcIP, a.SrcIP),
		vrrpv2Encoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *VRRPv2) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *VRRPv2) NetcapType() Type {
	return Type_NC_VRRPv2
}
