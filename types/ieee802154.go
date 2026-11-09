package types

import (
	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
	"time"
)

var fieldsIEEE802154 = []string{"Timestamp", "FrameControl", "FrameType", "FrameVersion", "Sequence", "SequenceSuppressed", "SourcePAN", "DestinationPAN", "Source", "Destination", "HeaderLength", "PayloadLength", "PayloadProtocol", "HasFCS", "FCSValid", "FCS"}

func (r *IEEE802154) CSVHeader() []string { return filter(fieldsIEEE802154) }
func (r *IEEE802154) CSVRecord() []string {
	return filter([]string{formatTimestamp(r.Timestamp), formatUint32(r.FrameControl), formatUint32(r.FrameType), formatUint32(r.FrameVersion), formatUint32(r.Sequence), strconv.FormatBool(r.SequenceSuppressed), r.SourcePAN, r.DestinationPAN, r.Source, r.Destination, formatUint32(r.HeaderLength), formatUint32(r.PayloadLength), r.PayloadProtocol, strconv.FormatBool(r.HasFCS), strconv.FormatBool(r.FCSValid), formatUint32(r.FCS)})
}
func (r *IEEE802154) Time() int64 { return r.Timestamp }
func (r *IEEE802154) JSON() (string, error) {
	c := *r
	c.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&c)
}
func (r *IEEE802154) Src() string                   { return r.Source }
func (r *IEEE802154) Dst() string                   { return r.Destination }
func (*IEEE802154) SetPacketContext(*PacketContext) {}
func (*IEEE802154) Analyze()                        {}
func (*IEEE802154) NetcapType() Type                { return Type_NC_IEEE802154 }

var ieee802154Metric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_ieee802154", Help: "IEEE 802.15.4 MAC frames"})

func (*IEEE802154) Inc() { ieee802154Metric.Inc() }

var ieee802154Encoder = encoder.NewValueEncoder()

func (r *IEEE802154) Encode() []string {
	values := r.CSVRecord()
	for i, name := range r.CSVHeader() {
		if name == "Timestamp" {
			values[i] = ieee802154Encoder.Int64(name, r.Timestamp)
		} else {
			values[i] = ieee802154Encoder.String(name, values[i])
		}
	}
	return values
}
