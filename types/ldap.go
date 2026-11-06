package types

import (
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsLDAP = []string{fieldTimestamp, fieldFlow, "CommunityID", fieldSrcIP, fieldDstIP, fieldSrcPort, fieldDstPort, "MessageID", "Operation", "DN", "Attributes", "ResultCode"}
var ldapEncoder = encoder.NewValueEncoder()
var ldapMetric = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "nc_ldap", Help: "LDAP audit records"}, []string{"operation"})

func (a *LDAP) CSVHeader() []string { return filter(fieldsLDAP) }
func (a *LDAP) CSVRecord() []string {
	b, _ := json.Marshal(a.Attributes)
	return filter([]string{formatTimestamp(a.Timestamp), a.Flow, a.CommunityID, a.SrcIP, a.DstIP, formatInt32(a.SrcPort), formatInt32(a.DstPort), formatInt32(a.MessageID), a.Operation, a.DN, string(b), formatInt32(a.ResultCode)})
}
func (a *LDAP) Time() int64 { return a.Timestamp }
func (a *LDAP) JSON() (string, error) {
	copy := *a
	copy.Timestamp /= 1000000
	return jsonMarshaler.MarshalToString(&copy)
}
func (a *LDAP) Inc()                            { ldapMetric.WithLabelValues(a.Operation).Inc() }
func (a *LDAP) SetPacketContext(*PacketContext) {}
func (a *LDAP) Src() string                     { return a.SrcIP }
func (a *LDAP) Dst() string                     { return a.DstIP }
func (a *LDAP) Encode() []string {
	b, _ := json.Marshal(a.Attributes)
	return filter([]string{ldapEncoder.Int64(fieldTimestamp, a.Timestamp), ldapEncoder.String(fieldFlow, a.Flow), ldapEncoder.String("CommunityID", a.CommunityID), ldapEncoder.String(fieldSrcIP, a.SrcIP), ldapEncoder.String(fieldDstIP, a.DstIP), ldapEncoder.Int32(fieldSrcPort, a.SrcPort), ldapEncoder.Int32(fieldDstPort, a.DstPort), ldapEncoder.Int32("MessageID", a.MessageID), ldapEncoder.String("Operation", a.Operation), ldapEncoder.String("DN", a.DN), ldapEncoder.String("Attributes", string(b)), ldapEncoder.Int32("ResultCode", a.ResultCode)})
}
func (a *LDAP) Analyze()         {}
func (a *LDAP) NetcapType() Type { return Type_NC_LDAP }
