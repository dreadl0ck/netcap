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
	fieldClient    = "Client"
	fieldServer    = "Server"
	fieldAuthToken = "AuthToken"
	fieldPass      = "Pass"
	fieldNumMails  = "NumMails"
)

var fieldsPOP3 = []string{
	fieldTimestamp,
	fieldClient,    // string
	fieldServer,    // string
	fieldAuthToken, // string
	fieldUser,      // string
	fieldPass,      // string
	fieldNumMails,  // []*Mail
}

// CSVHeader returns the CSV header for the audit record.
func (a *POP3) CSVHeader() []string {
	return filter(fieldsPOP3)
}

// CSVRecord returns the CSV record for the audit record.
func (a *POP3) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.ClientIP,                   // string
		a.ServerIP,                   // string
		a.AuthToken,                  // string
		a.User,                       // string
		a.Pass,                       // string
		strconv.Itoa(len(a.MailIDs)), // []*Mail
	})
}

// Time returns the timestamp associated with the audit record.
func (a *POP3) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *POP3) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var pop3Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_POP3.String()),
		Help: Type_NC_POP3.String() + " audit records",
	},
	fieldsPOP3[1:],
)

// Inc increments the metrics for the audit record.
func (a *POP3) Inc() {
	pop3Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *POP3) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *POP3) Src() string {
	return a.ClientIP
}

// Dst returns the destination address of the audit record.
func (a *POP3) Dst() string {
	return a.ServerIP
}

var pop3Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *POP3) Encode() []string {
	return filter([]string{
		pop3Encoder.Int64(fieldTimestamp, a.Timestamp),
		pop3Encoder.String(fieldClientIP, a.ClientIP),   // string
		pop3Encoder.String(fieldServerIP, a.ServerIP),   // string
		pop3Encoder.String(fieldAuthToken, a.AuthToken), // string
		pop3Encoder.String(fieldUser, a.User),           // string
		pop3Encoder.String(fieldPass, a.Pass),           // string
		pop3Encoder.Int(fieldNumMails, len(a.MailIDs)),  // []*Mail
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *POP3) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *POP3) NetcapType() Type {
	return Type_NC_POP3
}
