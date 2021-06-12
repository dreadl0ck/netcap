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
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldID           = "ID"
	fieldQR           = "QR"
	fieldOpCode       = "OpCode"
	fieldAA           = "AA"
	fieldTC           = "TC"
	fieldRD           = "RD"
	fieldRA           = "RA"
	fieldZ            = "Z"
	fieldResponseCode = "ResponseCode"
	fieldQDCount      = "QDCount"
	fieldANCount      = "ANCount"
	fieldNSCount      = "NSCount"
	fieldARCount      = "ARCount"
	fieldQuestions    = "Questions"
	fieldAnswers      = "Answers"
	fieldAuthorities  = "Authorities"
	fieldAdditionals  = "Additionals"
)

var fieldsDNS = []string{
	fieldTimestamp,
	fieldID,           // int32
	fieldQR,           // bool
	fieldOpCode,       // int32
	fieldAA,           // bool
	fieldTC,           // bool
	fieldRD,           // bool
	fieldRA,           // bool
	fieldZ,            // int32
	fieldResponseCode, // int32
	fieldQDCount,      // int32
	fieldANCount,      // int32
	fieldNSCount,      // int32
	fieldARCount,      // int32
	fieldQuestions,    // []*DNSQuestion
	fieldAnswers,      // []*DNSResourceRecord
	fieldAuthorities,  // []*DNSResourceRecord
	fieldAdditionals,  // []*DNSResourceRecord
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (d *DNS) CSVHeader() []string {
	return filter(fieldsDNS)
}

// CSVRecord returns the CSV record for the audit record.
func (d *DNS) CSVRecord() []string {
	var (
		questions   = make([]string, len(d.Questions))
		answers     = make([]string, len(d.Answers))
		authorities = make([]string, len(d.Authorities))
		additionals = make([]string, len(d.Additionals))
	)
	for _, q := range d.Questions {
		questions = append(questions, q.toString())
	}
	for _, q := range d.Answers {
		answers = append(questions, q.toString())
	}
	for _, q := range d.Authorities {
		authorities = append(questions, q.toString())
	}
	for _, q := range d.Additionals {
		additionals = append(questions, q.toString())
	}

	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatInt32(d.ID),             // int32
		strconv.FormatBool(d.QR),      // bool
		formatInt32(d.OpCode),         // int32
		strconv.FormatBool(d.AA),      // bool
		strconv.FormatBool(d.TC),      // bool
		strconv.FormatBool(d.RD),      // bool
		strconv.FormatBool(d.RA),      // bool
		formatInt32(d.Z),              // int32
		formatInt32(d.ResponseCode),   // int32
		formatInt32(d.QDCount),        // int32
		formatInt32(d.ANCount),        // int32
		formatInt32(d.NSCount),        // int32
		formatInt32(d.ARCount),        // int32
		strings.Join(questions, ""),   // []*DNSQuestion
		strings.Join(answers, ""),     // []*DNSResourceRecord
		strings.Join(authorities, ""), // []*DNSResourceRecord
		strings.Join(additionals, ""), // []*DNSResourceRecord
		d.SrcIP,
		d.DstIP,
		formatInt32(d.SrcPort),
		formatInt32(d.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (d *DNS) Time() int64 {
	return d.Timestamp
}

func (q *DNSQuestion) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(q.Name)
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.Class))
	b.WriteString(StructureEnd)
	return b.String()
}

func (q *DNSResourceRecord) toString() string {
	var txts []string
	for _, t := range q.TXTs {
		txts = append(txts, string(t))
	}
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(q.Name)
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.Class))
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(q.TTL))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.DataLength))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(q.Data))
	b.WriteString(FieldSeparator)
	b.WriteString(q.IP)
	b.WriteString(FieldSeparator)
	b.WriteString(string(q.NS))
	b.WriteString(FieldSeparator)
	b.WriteString(string(q.CNAME))
	b.WriteString(FieldSeparator)
	b.WriteString(string(q.PTR))
	b.WriteString(FieldSeparator)
	b.WriteString(q.SOA.toString())
	b.WriteString(FieldSeparator)
	b.WriteString(q.SRV.toString())
	b.WriteString(FieldSeparator)
	b.WriteString(q.MX.toString())
	b.WriteString(FieldSeparator)
	b.WriteString(join(txts...))
	b.WriteString(StructureEnd)
	return b.String()
}

func (q *DNSSOA) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(string(q.MName))
	b.WriteString(FieldSeparator)
	b.WriteString(string(q.RName))
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(q.Serial))
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(q.Refresh))
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(q.Retry))
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(q.Expire))
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(q.Minimum))
	b.WriteString(StructureEnd)
	return b.String()
}

func (q *DNSSRV) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(q.Priority))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.Weight))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(q.Port))
	b.WriteString(FieldSeparator)
	b.WriteString(string(q.Name))
	b.WriteString(StructureEnd)
	return b.String()
}

func (q *DNSMX) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(q.Preference))
	b.WriteString(FieldSeparator)
	b.WriteString(q.Name)
	b.WriteString(StructureEnd)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (d *DNS) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var dnsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DNS.String()),
		Help: Type_NC_DNS.String() + " audit records",
	},
	fieldsDNS[1:],
)

// Inc increments the metrics for the audit record.
func (d *DNS) Inc() {
	dnsMetric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DNS) SetPacketContext(ctx *PacketContext) {
	d.SrcIP = ctx.SrcIP
	d.DstIP = ctx.DstIP
	d.SrcPort = ctx.SrcPort
	d.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (d *DNS) Src() string {
	return d.SrcIP
}

// Dst returns the destination address of the audit record.
func (d *DNS) Dst() string {
	return d.DstIP
}

var dnsEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *DNS) Encode() []string {

	var (
		questions   = make([]string, len(d.Questions))
		answers     = make([]string, len(d.Answers))
		authorities = make([]string, len(d.Authorities))
		additionals = make([]string, len(d.Additionals))
	)
	for _, q := range d.Questions {
		questions = append(questions, q.toString())
	}
	for _, q := range d.Answers {
		answers = append(questions, q.toString())
	}
	for _, q := range d.Authorities {
		authorities = append(questions, q.toString())
	}
	for _, q := range d.Additionals {
		additionals = append(questions, q.toString())
	}

	return filter([]string{
		dnsEncoder.Int64(fieldTimestamp, d.Timestamp),
		dnsEncoder.Int32(fieldID, d.ID),                                    // int32
		dnsEncoder.Bool(d.QR),                                              // bool
		dnsEncoder.Int32(fieldOpCode, d.OpCode),                            // int32
		dnsEncoder.Bool(d.AA),                                              // bool
		dnsEncoder.Bool(d.TC),                                              // bool
		dnsEncoder.Bool(d.RD),                                              // bool
		dnsEncoder.Bool(d.RA),                                              // bool
		dnsEncoder.Int32(fieldZ, d.Z),                                      // int32
		dnsEncoder.Int32(fieldResponseCode, d.ResponseCode),                // int32
		dnsEncoder.Int32(fieldQDCount, d.QDCount),                          // int32
		dnsEncoder.Int32(fieldANCount, d.ANCount),                          // int32
		dnsEncoder.Int32(fieldNSCount, d.NSCount),                          // int32
		dnsEncoder.Int32(fieldARCount, d.ARCount),                          // int32
		dnsEncoder.String(fieldQuestions, strings.Join(questions, "")),     // []*DNSQuestion
		dnsEncoder.String(fieldAnswers, strings.Join(answers, "")),         // []*DNSResourceRecord
		dnsEncoder.String(fieldAuthorities, strings.Join(authorities, "")), // []*DNSResourceRecord
		dnsEncoder.String(fieldAdditionals, strings.Join(additionals, "")), // []*DNSResourceRecord
		dnsEncoder.String(fieldSrcIP, d.SrcIP),
		dnsEncoder.String(fieldDstIP, d.DstIP),
		dnsEncoder.Int32(fieldSrcPort, d.SrcPort),
		dnsEncoder.Int32(fieldDstPort, d.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *DNS) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *DNS) NetcapType() Type {
	return Type_NC_DNS
}
