package types

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsNBNS = []string{"Timestamp", "SrcIP", "DstIP", "SrcPort", "DstPort", "CommunityID", "ID", "Response", "OpCode", "ResponseCode", "Names"}

func (r *NBNS) CSVHeader() []string { return filter(fieldsNBNS) }
func (r *NBNS) CSVRecord() []string {
	names, _ := json.Marshal(r.Names)
	return filter([]string{formatTimestamp(r.Timestamp), r.SrcIP, r.DstIP, formatInt32(r.SrcPort), formatInt32(r.DstPort), r.CommunityID, formatUint32(r.ID), strconv.FormatBool(r.Response), formatUint32(r.OpCode), formatUint32(r.ResponseCode), string(names)})
}
func (r *NBNS) Time() int64 { return r.Timestamp }
func (r *NBNS) JSON() (string, error) {
	c := *r
	c.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&c)
}
func (r *NBNS) Src() string { return r.SrcIP }
func (r *NBNS) Dst() string { return r.DstIP }
func (r *NBNS) SetPacketContext(c *PacketContext) {
	r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.CommunityID = c.SrcIP, c.DstIP, c.SrcPort, c.DstPort, c.CommunityID
}
func (*NBNS) Analyze()         {}
func (*NBNS) NetcapType() Type { return Type_NC_NBNS }

var nbnsMetric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_nbns", Help: "NetBIOS name service records"})

func (*NBNS) Inc() { nbnsMetric.Inc() }

var nbnsEncoder = encoder.NewValueEncoder()

func (r *NBNS) Encode() []string {
	values := r.CSVRecord()
	for i, name := range r.CSVHeader() {
		if name == "Timestamp" {
			values[i] = nbnsEncoder.Int64(name, r.Timestamp)
		} else {
			values[i] = nbnsEncoder.String(name, values[i])
		}
	}
	return values
}
