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
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldSeqNum     = "SeqNum"
	fieldAckNum     = "AckNum"
	fieldDataOffset = "DataOffset"
	fieldFIN        = "FIN"
	fieldSYN        = "SYN"
	fieldRST        = "RST"
	fieldPSH        = "PSH"
	fieldACK        = "ACK"
	fieldURG        = "URG"
	fieldECE        = "ECE"
	fieldCWR        = "CWR"
	fieldNS         = "NS"
	fieldWindow     = "Window"
	fieldUrgent     = "Urgent"
)

var fieldsTCP = []string{
	fieldTimestamp,
	fieldSrcPort,
	fieldDstPort,
	fieldSeqNum,
	fieldAckNum,
	fieldDataOffset,
	fieldFIN,
	fieldSYN,
	fieldRST,
	fieldPSH,
	fieldACK,
	fieldURG,
	fieldECE,
	fieldCWR,
	fieldNS,
	fieldWindow,
	fieldChecksum,
	fieldUrgent,
	//fieldOptions,
	fieldPayloadEntropy,
	fieldPayloadSize,
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (t *TCP) CSVHeader() []string {
	return filter(fieldsTCP)
}

// CSVRecord returns the CSV record for the audit record.
func (t *TCP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(t.Timestamp),                      // int64
		formatInt32(t.SrcPort),                            // int32
		formatInt32(t.DstPort),                            // int32
		strconv.FormatUint(uint64(t.SeqNum), 10),          // uint32
		strconv.FormatUint(uint64(t.AckNum), 10),          // uint32
		formatInt32(t.DataOffset),                         // int32
		strconv.FormatBool(t.FIN),                         // bool
		strconv.FormatBool(t.SYN),                         // bool
		strconv.FormatBool(t.RST),                         // bool
		strconv.FormatBool(t.PSH),                         // bool
		strconv.FormatBool(t.ACK),                         // bool
		strconv.FormatBool(t.URG),                         // bool
		strconv.FormatBool(t.ECE),                         // bool
		strconv.FormatBool(t.CWR),                         // bool
		strconv.FormatBool(t.NS),                          // bool
		formatInt32(t.Window),                             // int32
		formatInt32(t.Checksum),                           // int32
		formatInt32(t.Urgent),                             // int32
		t.getOptionString(),                               // []*TCPOption
		strconv.FormatFloat(t.PayloadEntropy, 'f', 8, 64), // float64
		formatInt32(t.PayloadSize),                        // int32
		t.SrcIP,
		t.DstIP,
	})
}

func (t *TCP) getOptionString() string {
	var b strings.Builder
	for _, o := range t.Options {
		b.WriteString(StructureBegin)
		b.WriteString(strconv.Itoa(int(o.OptionType)))
		b.WriteString(FieldSeparator)
		b.WriteString(strconv.Itoa(int(o.OptionLength)))
		b.WriteString(FieldSeparator)
		b.WriteString(hex.EncodeToString(o.OptionData))
		b.WriteString(StructureEnd)
	}
	return b.String()
}

// Time returns the timestamp associated with the audit record.
func (t *TCP) Time() int64 {
	return t.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (t *TCP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	t.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(t)
}

var (
	tcpMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_TCP.String()),
			Help: Type_NC_TCP.String() + " audit records",
		},
		fieldsTCPMetrics,
	)
	tcpPayloadEntropy = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_TCP.String()) + "_entropy",
			Help:    Type_NC_TCP.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// []string{"SrcPort", "DstPort"},
		[]string{},
	)
	tcpPayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_TCP.String()) + "_size",
			Help:    Type_NC_TCP.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// []string{"SrcPort", "DstPort"},
		[]string{},
	)
)

var fieldsTCPMetrics = []string{
	fieldSrcPort,
	fieldDstPort,
	// fieldSeqNum,
	// fieldAckNum,
	fieldDataOffset,
	fieldFIN,
	fieldSYN,
	fieldRST,
	fieldPSH,
	fieldACK,
	fieldURG,
	fieldECE,
	fieldCWR,
	fieldNS,
	// fieldWindow,
	fieldUrgent,
	// fieldPadding,
	// fieldOptions,
}

func (t *TCP) metricValues() []string {
	return []string{
		formatInt32(t.SrcPort), // int32
		formatInt32(t.DstPort), // int32
		// strconv.FormatUint(uint64(t.SeqNum), 10), // uint32
		// strconv.FormatUint(uint64(t.AckNum), 10), // uint32
		formatInt32(t.DataOffset), // int32
		strconv.FormatBool(t.FIN), // bool
		strconv.FormatBool(t.SYN), // bool
		strconv.FormatBool(t.RST), // bool
		strconv.FormatBool(t.PSH), // bool
		strconv.FormatBool(t.ACK), // bool
		strconv.FormatBool(t.URG), // bool
		strconv.FormatBool(t.ECE), // bool
		strconv.FormatBool(t.CWR), // bool
		strconv.FormatBool(t.NS),  // bool
		// formatInt32(t.Window),     // int32
		formatInt32(t.Urgent), // int32
		// string(t.Padding),                        // []byte
		// t.GetOptionString(),                      // []*TCPOption
	}
}

// Inc increments the metrics for the audit record.
func (t *TCP) Inc() {
	tcpMetric.WithLabelValues(t.metricValues()...).Inc()
	tcpPayloadEntropy.WithLabelValues().Observe(t.PayloadEntropy)
	tcpPayloadSize.WithLabelValues().Observe(float64(t.PayloadSize))
}

// SetPacketContext sets the associated packet context for the audit record.
func (t *TCP) SetPacketContext(ctx *PacketContext) {
	t.SrcIP = ctx.SrcIP
	t.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (t *TCP) Src() string {
	return t.SrcIP
}

// Dst returns the destination address of the audit record.
func (t *TCP) Dst() string {
	return t.DstIP
}

var tcpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (t *TCP) Encode() []string {
	return filter([]string{
		tcpEncoder.Int64(fieldTimestamp, t.Timestamp),   // int64
		tcpEncoder.Int32(fieldSrcPort, t.SrcPort),       // int32
		tcpEncoder.Int32(fieldDstPort, t.DstPort),       // int32
		tcpEncoder.Uint32(fieldSeqNum, t.SeqNum),        // uint32
		tcpEncoder.Uint32(fieldAckNum, t.AckNum),        // uint32
		tcpEncoder.Int32(fieldDataOffset, t.DataOffset), // int32
		tcpEncoder.Bool(t.FIN),                          // bool
		tcpEncoder.Bool(t.SYN),                          // bool
		tcpEncoder.Bool(t.RST),                          // bool
		tcpEncoder.Bool(t.PSH),                          // bool
		tcpEncoder.Bool(t.ACK),                          // bool
		tcpEncoder.Bool(t.URG),                          // bool
		tcpEncoder.Bool(t.ECE),                          // bool
		tcpEncoder.Bool(t.CWR),                          // bool
		tcpEncoder.Bool(t.NS),                           // bool
		tcpEncoder.Int32(fieldWindow, t.Window),         // int32
		tcpEncoder.Int32(fieldChecksum, t.Checksum),     // int32
		tcpEncoder.Int32(fieldUrgent, t.Urgent),         // int32
		//tcpEncoder.String(fieldOptions, t.getOptionString()),      // []*TCPOption
		tcpEncoder.Float64(fieldPayloadEntropy, t.PayloadEntropy), // float64
		tcpEncoder.Int32(fieldPayloadSize, t.PayloadSize),         // int32
		tcpEncoder.Int64(fieldSrcIP, ipToInt64(t.SrcIP)),
		tcpEncoder.Int64(fieldDstIP, ipToInt64(t.DstIP)),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (t *TCP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (t *TCP) NetcapType() Type {
	return Type_NC_TCP
}
