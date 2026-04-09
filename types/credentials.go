/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package types

import (
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

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
