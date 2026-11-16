package types

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsLinkFrame = []string{"Timestamp", "LinkType", "Protocol", "Source", "Destination", "HeaderLength", "PayloadLength", "PayloadProtocol", "Fields", "Header", "Payload", "Qualifications"}

func (r *LinkFrame) CSVHeader() []string { return filter(fieldsLinkFrame) }
func (r *LinkFrame) CSVRecord() []string {
	fields, _ := json.Marshal(r.Fields)
	return filter([]string{formatTimestamp(r.Timestamp), formatUint32(r.LinkType), r.Protocol, r.Source, r.Destination, formatUint32(r.HeaderLength), formatUint32(r.PayloadLength), r.PayloadProtocol, string(fields), hex.EncodeToString(r.Header), hex.EncodeToString(r.Payload), strings.Join(r.Qualifications, ";")})
}
func (r *LinkFrame) Time() int64 { return r.Timestamp }
func (r *LinkFrame) JSON() (string, error) {
	c := *r
	c.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&c)
}
func (r *LinkFrame) Src() string                   { return r.Source }
func (r *LinkFrame) Dst() string                   { return r.Destination }
func (*LinkFrame) SetPacketContext(*PacketContext) {}
func (*LinkFrame) Analyze()                        {}
func (*LinkFrame) NetcapType() Type                { return Type_NC_LinkFrame }

var linkFrameMetric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_linkframe", Help: "Validated capture link framing records"})

func (*LinkFrame) Inc() { linkFrameMetric.Inc() }

var linkFrameEncoder = encoder.NewValueEncoder()

func (r *LinkFrame) Encode() []string {
	values := r.CSVRecord()
	for i, name := range r.CSVHeader() {
		if name == "Timestamp" {
			values[i] = linkFrameEncoder.Int64(name, r.Timestamp)
		} else {
			values[i] = linkFrameEncoder.String(name, values[i])
		}
	}
	return values
}
