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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsSMTP = []string{
	"Timestamp",
	"IsEncrypted",   // bool
	"IsResponse",    // bool
	"ResponseLines", // []*SMTPResponse
	"Command",       // *SMTPCommand
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

// CSVHeader returns the CSV header for the audit record.
func (a *SMTP) CSVHeader() []string {
	return filter(fieldsSMTP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *SMTP) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	var responses []string
	for _, r := range a.ResponseLines {
		responses = append(responses, r.getString())
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.IsEncrypted), // bool
		strconv.FormatBool(a.IsResponse),  // bool
		join(responses...),                // []*SMTPResponse
		a.Command.getString(),             // *SMTPCommand
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *SMTP) Time() string {
	return a.Timestamp
}

func (a SMTPCommand) getString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(a.Command))
	b.WriteString(Separator)
	b.WriteString(a.Parameter)
	b.WriteString(End)
	return b.String()
}

func (a SMTPResponse) getString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(a.ResponseCode))
	b.WriteString(Separator)
	b.WriteString(a.Parameter)
	b.WriteString(End)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (a *SMTP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var smtpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SMTP.String()),
		Help: Type_NC_SMTP.String() + " audit records",
	},
	fieldsSMTP[1:],
)

func init() {
	prometheus.MustRegister(smtpMetric)
}

// Inc increments the metrics for the audit record.
func (a *SMTP) Inc() {
	smtpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *SMTP) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

// Src returns the source address of the audit record.
func (a *SMTP) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (a *SMTP) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
