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
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldService  = "Service"
	fieldFlow     = "Flow"
	fieldUser     = "User"
	fieldPassword = "Password"
	fieldNotes    = "Notes"
)

var fieldsSecret = []string{
	fieldTimestamp,
	fieldService,  // string
	fieldFlow,     // string
	fieldUser,     // string
	fieldPassword, // string
	fieldNotes,    // string
}

// CSVHeader returns the CSV header for the audit record.
func (c *Secret) CSVHeader() []string {
	return filter(fieldsSecret)
}

// CSVRecord returns the CSV record for the audit record.
func (c *Secret) CSVRecord() []string {
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
func (c *Secret) Time() int64 {
	return c.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (c *Secret) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	copy := *c
	copy.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(&copy)
}

var secretMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Secret.String()),
		Help: Type_NC_Secret.String() + " audit records",
	},
	[]string{fieldService},
)

// Inc increments the metrics for the audit record.
func (c *Secret) Inc() {
	secretMetric.WithLabelValues(c.Service).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Secret) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (c *Secret) Src() string {
	src, _, ok := strings.Cut(c.Flow, "->")
	if !ok {
		return ""
	}
	return secretFlowAddress(src)
}

// Dst returns the destination address of the audit record.
func (c *Secret) Dst() string {
	_, dst, ok := strings.Cut(c.Flow, "->")
	if !ok {
		return ""
	}
	return secretFlowAddress(dst)
}

// Flow is an observed directional tuple, not a claim about authentication roles.
func secretFlowAddress(endpoint string) string {
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap.Addr().String()
	}
	// Historical flow identifiers render IPv6 without brackets.
	i := strings.LastIndexByte(endpoint, ':')
	if i < 0 {
		return ""
	}
	if _, err := strconv.ParseUint(endpoint[i+1:], 10, 16); err != nil {
		return ""
	}
	if addr, err := netip.ParseAddr(endpoint[:i]); err == nil {
		return addr.String()
	}
	return ""
}

var secretEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (c *Secret) Encode() []string {
	return filter([]string{
		secretEncoder.Int64(fieldTimestamp, c.Timestamp),
		secretEncoder.String(fieldService, c.Service),
		secretEncoder.String(fieldFlow, c.Flow),
		secretEncoder.String(fieldUser, c.User),
		secretEncoder.String(fieldPassword, c.Password),
		secretEncoder.String(fieldNotes, c.Notes),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (c *Secret) Analyze() {
}

// NetcapType returns the type of the current audit record
func (c *Secret) NetcapType() Type {
	return Type_NC_Secret
}
