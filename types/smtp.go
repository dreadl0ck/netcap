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
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldIsEncrypted = "IsEncrypted"
	fieldMailIDs     = "MailIDs"
	fieldCommands    = "Commands"
)

var fieldsSMTP = []string{
	fieldTimestamp,
	fieldIsEncrypted, // bool
	fieldIsResponse,  // bool
	fieldMailIDs,     // []string
	fieldCommands,    // []string
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *SMTP) CSVHeader() []string {
	return filter(fieldsSMTP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *SMTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.IsEncrypted), // bool
		strconv.FormatBool(a.IsResponse),  // bool
		join(a.MailIDs...),
		join(a.Commands...),
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *SMTP) Time() int64 {
	return a.Timestamp
}

func (a SMTPCommand) getString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(a.Command))
	b.WriteString(FieldSeparator)
	b.WriteString(a.Parameter)
	b.WriteString(StructureEnd)
	return b.String()
}

func (a SMTPResponse) getString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(a.ResponseCode))
	b.WriteString(FieldSeparator)
	b.WriteString(a.Parameter)
	b.WriteString(StructureEnd)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (a *SMTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var smtpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SMTP.String()),
		Help: Type_NC_SMTP.String() + " audit records",
	},
	fieldsSMTP[1:],
)

// Inc increments the metrics for the audit record.
func (a *SMTP) Inc() {
	smtpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *SMTP) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
	a.SrcPort = ctx.SrcPort
	a.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (a *SMTP) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *SMTP) Dst() string {
	return a.DstIP
}

var smtpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *SMTP) Encode() []string {
	return filter([]string{
		smtpEncoder.Int64(fieldTimestamp, a.Timestamp),
		smtpEncoder.Bool(a.IsEncrypted), // bool
		smtpEncoder.Bool(a.IsResponse),  // bool
		smtpEncoder.String(fieldMailIDs, join(a.MailIDs...)),
		smtpEncoder.String(fieldCommands, join(a.Commands...)),
		smtpEncoder.String(fieldSrcIP, a.SrcIP),
		smtpEncoder.String(fieldDstIP, a.DstIP),
		smtpEncoder.Int32(fieldSrcPort, a.SrcPort),
		smtpEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *SMTP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *SMTP) NetcapType() Type {
	return Type_NC_SMTP
}
