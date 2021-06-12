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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldService  = "Service"
	fieldFlow     = "Flow"
	fieldUser     = "User"
	fieldPassword = "Password"
	fieldNotes    = "Notes"
)

var fieldsCredentials = []string{
	fieldTimestamp,
	fieldService,  // string
	fieldFlow,     // string
	fieldUser,     // string
	fieldPassword, // string
	fieldNotes,    // string
}

// CSVHeader returns the CSV header for the audit record.
func (c *Credentials) CSVHeader() []string {
	return filter(fieldsCredentials)
}

// CSVRecord returns the CSV record for the audit record.
func (c *Credentials) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(c.Timestamp),
		c.Service,
		c.Flow,
		c.User,
		c.Password,
		c.Notes,
	})
}

// Time returns the timestamp associated with the audit record.
func (c *Credentials) Time() int64 {
	return c.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (c *Credentials) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	c.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(c)
}

var credentialsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Credentials.String()),
		Help: Type_NC_Credentials.String() + " audit records",
	},
	fieldsCredentials[1:],
)

// Inc increments the metrics for the audit record.
func (c *Credentials) Inc() {
	credentialsMetric.WithLabelValues(c.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Credentials) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for Credentials and return them here.
// Src returns the source address of the audit record.
func (c *Credentials) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for Credentials and return them here.
// Dst returns the destination address of the audit record.
func (c *Credentials) Dst() string {
	return ""
}

var credentialsEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (c *Credentials) Encode() []string {
	return filter([]string{
		credentialsEncoder.Int64(fieldTimestamp, c.Timestamp),
		credentialsEncoder.String(fieldService, c.Service),
		credentialsEncoder.String(fieldFlow, c.Flow),
		credentialsEncoder.String(fieldUser, c.User),
		credentialsEncoder.String(fieldPassword, c.Password),
		credentialsEncoder.String(fieldNotes, c.Notes),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (c *Credentials) Analyze() {
}

// NetcapType returns the type of the current audit record
func (c *Credentials) NetcapType() Type {
	return Type_NC_Credentials
}
