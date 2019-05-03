/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
}

func (d DNS) CSVHeader() []string {
	return filter(fieldsDNS)
}

func (d DNS) CSVRecord() []string {
	var (
		questions, answers, authorities, additionals []string
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
	})
}

func (d DNS) NetcapTimestamp() string {
	return d.Timestamp
}

func (q DNSQuestion) ToString() string {
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

func (q DNSResourceRecord) ToString() string {
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

func (a DNS) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
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

func (a DNS) Inc() {
	dnsMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}
