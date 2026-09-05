package types

import (
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsTLSRecord = []string{
	fieldTimestamp, fieldSrcIP, fieldDstIP, fieldSrcPort, fieldDstPort, fieldCommunityID,
	"Flow", "Direction", "Index", "Offset", "ContentType", "RecordVersion", "Length", "ObservedLength",
	"HeaderComplete", "Incomplete", "Loss", "SkippedBytes", "Status", "PlaintextAlert", "AlertLevel", "AlertDescription", "AlertState",
}

func (r *TLSRecord) CSVHeader() []string { return filter(fieldsTLSRecord) }
func (r *TLSRecord) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(r.Timestamp), r.SrcIP, r.DstIP, formatInt32(r.SrcPort), formatInt32(r.DstPort), r.CommunityID,
		r.Flow, r.Direction, strconv.FormatUint(r.Index, 10), strconv.FormatUint(r.Offset, 10), formatUint32(r.ContentType),
		formatUint32(r.RecordVersion), formatUint32(r.Length), formatUint32(r.ObservedLength),
		strconv.FormatBool(r.HeaderComplete), strconv.FormatBool(r.Incomplete), strconv.FormatBool(r.Loss), strconv.FormatInt(r.SkippedBytes, 10),
		r.Status, strconv.FormatBool(r.PlaintextAlert), formatUint32(r.AlertLevel), formatUint32(r.AlertDescription), r.AlertState,
	})
}
func (r *TLSRecord) Time() int64 { return r.Timestamp }
func (r *TLSRecord) JSON() (string, error) {
	copy := *r
	copy.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&copy)
}

var tlsRecordMetric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_tlsrecord", Help: "TLS record audit records"})

func (r *TLSRecord) Inc() { tlsRecordMetric.Inc() }
func (r *TLSRecord) SetPacketContext(ctx *PacketContext) {
	r.SrcIP, r.DstIP, r.SrcPort, r.DstPort = ctx.SrcIP, ctx.DstIP, ctx.SrcPort, ctx.DstPort
	r.CommunityID = ctx.CommunityID
}
func (r *TLSRecord) Src() string      { return r.SrcIP }
func (r *TLSRecord) Dst() string      { return r.DstIP }
func (r *TLSRecord) Analyze()         {}
func (r *TLSRecord) NetcapType() Type { return Type_NC_TLSRecord }

var tlsRecordEncoder = encoder.NewValueEncoder()

func (r *TLSRecord) Encode() []string {
	return filter([]string{
		tlsRecordEncoder.Int64(fieldTimestamp, r.Timestamp), tlsRecordEncoder.String(fieldSrcIP, r.SrcIP), tlsRecordEncoder.String(fieldDstIP, r.DstIP),
		tlsRecordEncoder.Int32(fieldSrcPort, r.SrcPort), tlsRecordEncoder.Int32(fieldDstPort, r.DstPort), tlsRecordEncoder.String(fieldCommunityID, r.CommunityID),
		tlsRecordEncoder.String("Flow", r.Flow), tlsRecordEncoder.String("Direction", r.Direction), tlsRecordEncoder.Uint64("Index", r.Index),
		tlsRecordEncoder.Uint64("Offset", r.Offset), tlsRecordEncoder.Uint32("ContentType", r.ContentType), tlsRecordEncoder.Uint32("RecordVersion", r.RecordVersion),
		tlsRecordEncoder.Uint32("Length", r.Length), tlsRecordEncoder.Uint32("ObservedLength", r.ObservedLength),
		tlsRecordEncoder.Bool(r.HeaderComplete), tlsRecordEncoder.Bool(r.Incomplete), tlsRecordEncoder.Bool(r.Loss), tlsRecordEncoder.Int64("SkippedBytes", r.SkippedBytes),
		tlsRecordEncoder.String("Status", r.Status), tlsRecordEncoder.Bool(r.PlaintextAlert), tlsRecordEncoder.Uint32("AlertLevel", r.AlertLevel),
		tlsRecordEncoder.Uint32("AlertDescription", r.AlertDescription), tlsRecordEncoder.String("AlertState", r.AlertState),
	})
}
