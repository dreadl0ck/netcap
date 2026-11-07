package types

import (
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsRTP = []string{"Timestamp", "SrcIP", "DstIP", "SrcPort", "DstPort", "CommunityID", "CallID", "SSRC", "Sequence", "ExtendedSequence", "MediaTimestamp", "ExtendedTimestamp", "PayloadType", "Encoding", "ClockRate", "Marker", "PayloadLength", "CSRC", "ExtensionProfile", "ExtensionLength", "PaddingLength", "Reordered"}

func (r *RTP) CSVHeader() []string { return filter(fieldsRTP) }
func (r *RTP) CSVRecord() []string {
	var csrc []string
	for _, c := range r.CSRC {
		csrc = append(csrc, formatUint32(c))
	}
	return filter([]string{formatTimestamp(r.Timestamp), r.SrcIP, r.DstIP, formatInt32(r.SrcPort), formatInt32(r.DstPort), r.CommunityID, r.CallID,
		formatUint32(r.SSRC), formatUint32(r.Sequence), strconv.FormatInt(r.ExtendedSequence, 10), formatUint32(r.MediaTimestamp), strconv.FormatInt(r.ExtendedTimestamp, 10),
		formatUint32(r.PayloadType), r.Encoding, formatUint32(r.ClockRate), strconv.FormatBool(r.Marker), formatUint32(r.PayloadLength), join(csrc...),
		formatUint32(r.ExtensionProfile), formatUint32(r.ExtensionLength), formatUint32(r.PaddingLength), strconv.FormatBool(r.Reordered)})
}
func (r *RTP) Time() int64 { return r.Timestamp }
func (r *RTP) JSON() (string, error) {
	c := *r
	c.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&c)
}
func (r *RTP) Src() string { return r.SrcIP }
func (r *RTP) Dst() string { return r.DstIP }
func (r *RTP) SetPacketContext(c *PacketContext) {
	r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.CommunityID = c.SrcIP, c.DstIP, c.SrcPort, c.DstPort, c.CommunityID
}
func (*RTP) Analyze()         {}
func (*RTP) NetcapType() Type { return Type_NC_RTP }

var rtpMetric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_rtp", Help: "RTP metadata records"})

func (*RTP) Inc() { rtpMetric.Inc() }

var rtpEncoder = encoder.NewValueEncoder()

func (r *RTP) Encode() []string {
	return encodeMediaCSV(r.CSVHeader(), r.CSVRecord(), r.Timestamp, rtpEncoder)
}

var fieldsDTMF = []string{"Timestamp", "SrcIP", "DstIP", "SrcPort", "DstPort", "CommunityID", "CallID", "SSRC", "MediaTimestamp", "ExtendedTimestamp", "Event", "Digit", "Volume", "Duration", "ClockRate", "PayloadType"}

func (r *DTMF) CSVHeader() []string { return filter(fieldsDTMF) }
func (r *DTMF) CSVRecord() []string {
	return filter([]string{formatTimestamp(r.Timestamp), r.SrcIP, r.DstIP, formatInt32(r.SrcPort), formatInt32(r.DstPort), r.CommunityID, r.CallID,
		formatUint32(r.SSRC), formatUint32(r.MediaTimestamp), strconv.FormatInt(r.ExtendedTimestamp, 10), formatUint32(r.Event), r.Digit,
		formatUint32(r.Volume), formatUint32(r.Duration), formatUint32(r.ClockRate), formatUint32(r.PayloadType)})
}
func (r *DTMF) Time() int64 { return r.Timestamp }
func (r *DTMF) JSON() (string, error) {
	c := *r
	c.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(&c)
}
func (r *DTMF) Src() string { return r.SrcIP }
func (r *DTMF) Dst() string { return r.DstIP }
func (r *DTMF) SetPacketContext(c *PacketContext) {
	r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.CommunityID = c.SrcIP, c.DstIP, c.SrcPort, c.DstPort, c.CommunityID
}
func (*DTMF) Analyze()         {}
func (*DTMF) NetcapType() Type { return Type_NC_DTMF }

var dtmfMetric = prometheus.NewCounter(prometheus.CounterOpts{Name: "nc_dtmf", Help: "Completed telephone events"})

func (*DTMF) Inc() { dtmfMetric.Inc() }

var dtmfEncoder = encoder.NewValueEncoder()

func (r *DTMF) Encode() []string {
	return encodeMediaCSV(r.CSVHeader(), r.CSVRecord(), r.Timestamp, dtmfEncoder)
}

func encodeMediaCSV(fields, values []string, timestamp int64, enc *encoder.ValueEncoder) []string {
	for i, name := range fields {
		switch name {
		case "Timestamp":
			values[i] = enc.Int64(name, timestamp)
		case "SrcIP", "DstIP", "CommunityID", "CallID", "Encoding", "Digit", "CSRC":
			values[i] = enc.String(name, values[i])
		case "Marker", "Reordered":
			values[i] = enc.Bool(values[i] == "true")
		default:
			if n, err := strconv.ParseInt(values[i], 10, 64); err == nil {
				values[i] = enc.Int64(name, n)
			}
		}
	}
	return values
}
