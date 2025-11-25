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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldTypeName        = "TypeName"
	fieldMyAS            = "MyAS"
	fieldHoldTime        = "HoldTime"
	fieldBGPIdentifier   = "BGPIdentifier"
	fieldWithdrawnRoutes = "WithdrawnRoutes"
	fieldNLRI            = "NLRI"
	fieldOrigin          = "Origin"
	fieldOriginName      = "OriginName"
	fieldASPath          = "ASPath"
	fieldNextHop         = "NextHop"
	fieldMED             = "MED"
	fieldLocalPref       = "LocalPref"
	fieldCommunities     = "Communities"
	fieldErrorCode       = "ErrorCode"
	fieldErrorCodeName   = "ErrorCodeName"
	fieldErrorSubcode    = "ErrorSubcode"
	fieldIsAnomalous     = "IsAnomalous"
	fieldAnomalyReason   = "AnomalyReason"
	fieldIsRouteHijack   = "IsRouteHijack"
	fieldPeerAS          = "PeerAS"
)

var fieldsBGP = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldLength,
	fieldType,
	fieldTypeName,
	fieldVersion,
	fieldMyAS,
	fieldHoldTime,
	fieldBGPIdentifier,
	fieldWithdrawnRoutes,
	fieldNLRI,
	fieldOrigin,
	fieldOriginName,
	fieldASPath,
	fieldNextHop,
	fieldMED,
	fieldLocalPref,
	fieldCommunities,
	fieldErrorCode,
	fieldErrorCodeName,
	fieldIsAnomalous,
	fieldIsRouteHijack,
	fieldPeerAS,
}

// CSVHeader returns the CSV header for the audit record.
func (b *BGP) CSVHeader() []string {
	return filter(fieldsBGP)
}

// CSVRecord returns the CSV record for the audit record.
func (b *BGP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(b.Timestamp),
		b.SrcIP,
		b.DstIP,
		formatInt32(b.SrcPort),
		formatInt32(b.DstPort),
		formatInt32(b.Length),
		formatInt32(b.Type),
		b.TypeName,
		formatInt32(b.Version),
		formatUint32(b.MyAS),
		formatInt32(b.HoldTime),
		b.BGPIdentifier,
		join(b.WithdrawnRoutes...),
		join(b.NLRI...),
		formatInt32(b.Origin),
		b.OriginName,
		joinUints(b.ASPath),
		b.NextHop,
		formatInt32(b.MED),
		formatInt32(b.LocalPref),
		join(b.Communities...),
		formatInt32(b.ErrorCode),
		b.ErrorCodeName,
		strconv.FormatBool(b.IsAnomalous),
		strconv.FormatBool(b.IsRouteHijack),
		formatUint32(b.PeerAS),
	})
}

// Time returns the timestamp associated with the audit record.
func (b *BGP) Time() int64 {
	return b.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (b *BGP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	b.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(b)
}

var bgpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_BGP.String()),
		Help: Type_NC_BGP.String() + " audit records",
	},
	fieldsBGP[1:],
)

// Inc increments the metrics for the audit record.
func (b *BGP) Inc() {
	bgpMetric.WithLabelValues(b.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (b *BGP) SetPacketContext(ctx *PacketContext) {
	b.SrcIP = ctx.SrcIP
	b.DstIP = ctx.DstIP
	b.SrcPort = ctx.SrcPort
	b.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (b *BGP) Src() string {
	return b.SrcIP
}

// Dst returns the destination address of the audit record.
func (b *BGP) Dst() string {
	return b.DstIP
}

var bgpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (b *BGP) Encode() []string {
	return filter([]string{
		bgpEncoder.Int64(fieldTimestamp, b.Timestamp),
		bgpEncoder.String(fieldSrcIP, b.SrcIP),
		bgpEncoder.String(fieldDstIP, b.DstIP),
		bgpEncoder.Int32(fieldSrcPort, b.SrcPort),
		bgpEncoder.Int32(fieldDstPort, b.DstPort),
		bgpEncoder.Int32(fieldLength, b.Length),
		bgpEncoder.Int32(fieldType, b.Type),
		bgpEncoder.String(fieldTypeName, b.TypeName),
		bgpEncoder.Int32(fieldVersion, b.Version),
		bgpEncoder.Uint32(fieldMyAS, b.MyAS),
		bgpEncoder.Int32(fieldHoldTime, b.HoldTime),
		bgpEncoder.String(fieldBGPIdentifier, b.BGPIdentifier),
		bgpEncoder.String(fieldWithdrawnRoutes, join(b.WithdrawnRoutes...)),
		bgpEncoder.String(fieldNLRI, join(b.NLRI...)),
		bgpEncoder.Int32(fieldOrigin, b.Origin),
		bgpEncoder.String(fieldOriginName, b.OriginName),
		bgpEncoder.String(fieldASPath, joinUints(b.ASPath)),
		bgpEncoder.String(fieldNextHop, b.NextHop),
		bgpEncoder.Int32(fieldMED, b.MED),
		bgpEncoder.Int32(fieldLocalPref, b.LocalPref),
		bgpEncoder.String(fieldCommunities, join(b.Communities...)),
		bgpEncoder.Int32(fieldErrorCode, b.ErrorCode),
		bgpEncoder.String(fieldErrorCodeName, b.ErrorCodeName),
		bgpEncoder.Bool(b.IsAnomalous),
		bgpEncoder.Bool(b.IsRouteHijack),
		bgpEncoder.Uint32(fieldPeerAS, b.PeerAS),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (b *BGP) Analyze() {}

// NetcapType returns the type of the current audit record
func (b *BGP) NetcapType() Type {
	return Type_NC_BGP
}

