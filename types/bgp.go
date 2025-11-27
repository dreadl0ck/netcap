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

	// AS Path Security Analysis
	fieldASPathLength    = "ASPathLength"
	fieldOriginAS        = "OriginAS"
	fieldHasPrivateAS    = "HasPrivateAS"
	fieldHasASPathLoop   = "HasASPathLoop"
	fieldHasBogonAS      = "HasBogonAS"
	fieldASPathSet       = "ASPathSet"
	fieldASPathConfedSeq = "ASPathConfedSeq"
	fieldASPathConfedSet = "ASPathConfedSet"

	// Prefix Security Analysis
	fieldPrefixCount       = "PrefixCount"
	fieldWithdrawnCount    = "WithdrawnCount"
	fieldSmallestPrefixLen = "SmallestPrefixLen"
	fieldLargestPrefixLen  = "LargestPrefixLen"
	fieldHasBogonPrefix    = "HasBogonPrefix"
	fieldHasDefaultRoute   = "HasDefaultRoute"
	fieldBogonPrefixes     = "BogonPrefixes"

	// Extended Communities
	fieldExtendedCommunities = "ExtendedCommunities"
	fieldLargeCommunities    = "LargeCommunities"
	fieldHasBlackholeComm    = "HasBlackholeComm"
	fieldHasNoExportComm     = "HasNoExportComm"
	fieldHasNoAdvertiseComm  = "HasNoAdvertiseComm"
	fieldHasNoPeerComm       = "HasNoPeerComm"

	// Session Security
	fieldOptionalParamLen     = "OptionalParamLen"
	fieldHasUnknownCapability = "HasUnknownCapability"
	fieldHasUnknownAttribute  = "HasUnknownAttribute"
	fieldUnknownAttrTypes     = "UnknownAttrTypes"

	// Aggregation Info
	fieldAggregatorAS = "AggregatorAS"
	fieldAggregatorIP = "AggregatorIP"
	fieldIsAggregated = "IsAggregated"

	// IPv6 Support
	fieldBGPIsIPv6        = "IsIPv6"
	fieldBGPIPv6NLRI      = "IPv6NLRI"
	fieldBGPIPv6Withdrawn = "IPv6Withdrawn"
	fieldBGPIPv6NextHop   = "IPv6NextHop"

	// Security Scoring
	fieldRiskScore   = "RiskScore"
	fieldRiskFactors = "RiskFactors"
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
	fieldAnomalyReason,
	fieldIsRouteHijack,
	fieldPeerAS,
	// AS Path Security Analysis
	fieldASPathLength,
	fieldOriginAS,
	fieldHasPrivateAS,
	fieldHasASPathLoop,
	fieldHasBogonAS,
	fieldASPathSet,
	fieldASPathConfedSeq,
	fieldASPathConfedSet,
	// Prefix Security Analysis
	fieldPrefixCount,
	fieldWithdrawnCount,
	fieldSmallestPrefixLen,
	fieldLargestPrefixLen,
	fieldHasBogonPrefix,
	fieldHasDefaultRoute,
	fieldBogonPrefixes,
	// Extended Communities
	fieldExtendedCommunities,
	fieldLargeCommunities,
	fieldHasBlackholeComm,
	fieldHasNoExportComm,
	fieldHasNoAdvertiseComm,
	fieldHasNoPeerComm,
	// Session Security
	fieldOptionalParamLen,
	fieldHasUnknownCapability,
	fieldHasUnknownAttribute,
	fieldUnknownAttrTypes,
	// Aggregation Info
	fieldAggregatorAS,
	fieldAggregatorIP,
	fieldIsAggregated,
	// IPv6 Support
	fieldBGPIsIPv6,
	fieldBGPIPv6NLRI,
	fieldBGPIPv6Withdrawn,
	fieldBGPIPv6NextHop,
	// Security Scoring
	fieldRiskScore,
	fieldRiskFactors,
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
		b.AnomalyReason,
		strconv.FormatBool(b.IsRouteHijack),
		formatUint32(b.PeerAS),
		// AS Path Security Analysis
		formatInt32(b.ASPathLength),
		formatUint32(b.OriginAS),
		strconv.FormatBool(b.HasPrivateAS),
		strconv.FormatBool(b.HasASPathLoop),
		strconv.FormatBool(b.HasBogonAS),
		joinUints(b.ASPathSet),
		joinUints(b.ASPathConfedSeq),
		joinUints(b.ASPathConfedSet),
		// Prefix Security Analysis
		formatInt32(b.PrefixCount),
		formatInt32(b.WithdrawnCount),
		formatInt32(b.SmallestPrefixLen),
		formatInt32(b.LargestPrefixLen),
		strconv.FormatBool(b.HasBogonPrefix),
		strconv.FormatBool(b.HasDefaultRoute),
		join(b.BogonPrefixes...),
		// Extended Communities
		join(b.ExtendedCommunities...),
		join(b.LargeCommunities...),
		strconv.FormatBool(b.HasBlackholeComm),
		strconv.FormatBool(b.HasNoExportComm),
		strconv.FormatBool(b.HasNoAdvertiseComm),
		strconv.FormatBool(b.HasNoPeerComm),
		// Session Security
		formatInt32(b.OptionalParamLen),
		strconv.FormatBool(b.HasUnknownCapability),
		strconv.FormatBool(b.HasUnknownAttribute),
		joinInts(b.UnknownAttrTypes),
		// Aggregation Info
		b.AggregatorAS,
		b.AggregatorIP,
		strconv.FormatBool(b.IsAggregated),
		// IPv6 Support
		strconv.FormatBool(b.IsIPv6),
		join(b.IPv6NLRI...),
		join(b.IPv6Withdrawn...),
		b.IPv6NextHop,
		// Security Scoring
		formatInt32(b.RiskScore),
		join(b.RiskFactors...),
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
		bgpEncoder.String(fieldAnomalyReason, b.AnomalyReason),
		bgpEncoder.Bool(b.IsRouteHijack),
		bgpEncoder.Uint32(fieldPeerAS, b.PeerAS),
		// AS Path Security Analysis
		bgpEncoder.Int32(fieldASPathLength, b.ASPathLength),
		bgpEncoder.Uint32(fieldOriginAS, b.OriginAS),
		bgpEncoder.Bool(b.HasPrivateAS),
		bgpEncoder.Bool(b.HasASPathLoop),
		bgpEncoder.Bool(b.HasBogonAS),
		bgpEncoder.String(fieldASPathSet, joinUints(b.ASPathSet)),
		bgpEncoder.String(fieldASPathConfedSeq, joinUints(b.ASPathConfedSeq)),
		bgpEncoder.String(fieldASPathConfedSet, joinUints(b.ASPathConfedSet)),
		// Prefix Security Analysis
		bgpEncoder.Int32(fieldPrefixCount, b.PrefixCount),
		bgpEncoder.Int32(fieldWithdrawnCount, b.WithdrawnCount),
		bgpEncoder.Int32(fieldSmallestPrefixLen, b.SmallestPrefixLen),
		bgpEncoder.Int32(fieldLargestPrefixLen, b.LargestPrefixLen),
		bgpEncoder.Bool(b.HasBogonPrefix),
		bgpEncoder.Bool(b.HasDefaultRoute),
		bgpEncoder.String(fieldBogonPrefixes, join(b.BogonPrefixes...)),
		// Extended Communities
		bgpEncoder.String(fieldExtendedCommunities, join(b.ExtendedCommunities...)),
		bgpEncoder.String(fieldLargeCommunities, join(b.LargeCommunities...)),
		bgpEncoder.Bool(b.HasBlackholeComm),
		bgpEncoder.Bool(b.HasNoExportComm),
		bgpEncoder.Bool(b.HasNoAdvertiseComm),
		bgpEncoder.Bool(b.HasNoPeerComm),
		// Session Security
		bgpEncoder.Int32(fieldOptionalParamLen, b.OptionalParamLen),
		bgpEncoder.Bool(b.HasUnknownCapability),
		bgpEncoder.Bool(b.HasUnknownAttribute),
		bgpEncoder.String(fieldUnknownAttrTypes, joinInts(b.UnknownAttrTypes)),
		// Aggregation Info
		bgpEncoder.String(fieldAggregatorAS, b.AggregatorAS),
		bgpEncoder.String(fieldAggregatorIP, b.AggregatorIP),
		bgpEncoder.Bool(b.IsAggregated),
		// IPv6 Support
		bgpEncoder.Bool(b.IsIPv6),
		bgpEncoder.String(fieldBGPIPv6NLRI, join(b.IPv6NLRI...)),
		bgpEncoder.String(fieldBGPIPv6Withdrawn, join(b.IPv6Withdrawn...)),
		bgpEncoder.String(fieldBGPIPv6NextHop, b.IPv6NextHop),
		// Security Scoring
		bgpEncoder.Int32(fieldRiskScore, b.RiskScore),
		bgpEncoder.String(fieldRiskFactors, join(b.RiskFactors...)),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (b *BGP) Analyze() {}

// NetcapType returns the type of the current audit record
func (b *BGP) NetcapType() Type {
	return Type_NC_BGP
}
