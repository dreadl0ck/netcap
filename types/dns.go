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

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsDNS = []string{
	"Timestamp",
	"ID",           // int32
	"QR",           // bool
	"OpCode",       // int32
	"AA",           // bool
	"TC",           // bool
	"RD",           // bool
	"RA",           // bool
	"Z",            // int32
	"ResponseCode", // int32
	"QDCount",      // int32
	"ANCount",      // int32
	"NSCount",      // int32
	"ARCount",      // int32
	"Questions",    // []*DNSQuestion
	"Answers",      // []*DNSResourceRecord
	"Authorities",  // []*DNSResourceRecord
	"Additionals",  // []*DNSResourceRecord
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
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
		questions = append(questions, q.ToString())
	}
	for _, q := range d.Answers {
		answers = append(questions, q.ToString())
	}
	for _, q := range d.Authorities {
		authorities = append(questions, q.ToString())
	}
	for _, q := range d.Additionals {
		additionals = append(questions, q.ToString())
	}
	// prevent accessing nil pointer
	if d.Context == nil {
		d.Context = &PacketContext{}
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
		d.Context.SrcIP,
		d.Context.DstIP,
		d.Context.SrcPort,
		d.Context.DstPort,
	})
}

// Time returns the timestamp associated with the audit record.
func (d *DNS) Time() string {
	return d.Timestamp
}

func (q *DNSQuestion) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(string(q.Name))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.Type))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.Class))
	b.WriteString(End)
	return b.String()
}

func (q *DNSResourceRecord) ToString() string {
	var txts []string
	for _, t := range q.TXTs {
		txts = append(txts, string(t))
	}
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(string(q.Name))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.Type))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.Class))
	b.WriteString(Separator)
	b.WriteString(formatUint32(q.TTL))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.DataLength))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(q.Data))
	b.WriteString(Separator)
	b.WriteString(q.IP)
	b.WriteString(Separator)
	b.WriteString(string(q.NS))
	b.WriteString(Separator)
	b.WriteString(string(q.CNAME))
	b.WriteString(Separator)
	b.WriteString(string(q.PTR))
	b.WriteString(Separator)
	b.WriteString(q.SOA.ToString())
	b.WriteString(Separator)
	b.WriteString(q.SRV.ToString())
	b.WriteString(Separator)
	b.WriteString(q.MX.ToString())
	b.WriteString(Separator)
	b.WriteString(join(txts...))
	b.WriteString(End)
	return b.String()
}

func (q *DNSSOA) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(string(q.MName))
	b.WriteString(Separator)
	b.WriteString(string(q.RName))
	b.WriteString(Separator)
	b.WriteString(formatUint32(q.Serial))
	b.WriteString(Separator)
	b.WriteString(formatUint32(q.Refresh))
	b.WriteString(Separator)
	b.WriteString(formatUint32(q.Retry))
	b.WriteString(Separator)
	b.WriteString(formatUint32(q.Expire))
	b.WriteString(Separator)
	b.WriteString(formatUint32(q.Minimum))
	b.WriteString(End)
	return b.String()
}

func (q *DNSSRV) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(q.Priority))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.Weight))
	b.WriteString(Separator)
	b.WriteString(formatInt32(q.Port))
	b.WriteString(Separator)
	b.WriteString(string(q.Name))
	b.WriteString(End)
	return b.String()
}

func (q *DNSMX) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(q.Preference))
	b.WriteString(Separator)
	b.WriteString(string(q.Name))
	b.WriteString(End)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (d *DNS) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(d)
}

var dnsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DNS.String()),
		Help: Type_NC_DNS.String() + " audit records",
	},
	fieldsDNS[1:],
)

func init() {
	prometheus.MustRegister(dnsMetric)
}

// Inc increments the metrics for the audit record.
func (d *DNS) Inc() {
	dnsMetric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DNS) SetPacketContext(ctx *PacketContext) {
	d.Context = ctx
}

// Src returns the source address of the audit record.
func (d *DNS) Src() string {
	if d.Context != nil {
		return d.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (d *DNS) Dst() string {
	if d.Context != nil {
		return d.Context.DstIP
	}
	return ""
}
