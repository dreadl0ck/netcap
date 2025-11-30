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
	fieldJa4ssh            = "Ja4ssh"
	fieldJa4sshSessionType = "Ja4sshSessionType"
)

var fieldsSSH = []string{
	fieldTimestamp,
	fieldJa4ssh,
	fieldFlow,
	fieldNotes,
	fieldJa4sshSessionType,
}

// CSVHeader returns the CSV header for the audit record.
func (a *SSH) CSVHeader() []string {
	return filter(fieldsSSH)
}

// CSVRecord returns the CSV record for the audit record.
func (a *SSH) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Ja4Ssh,
		a.Flow,
		a.Notes,
		a.Ja4SshSessionType,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *SSH) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *SSH) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fieldsSSHMetric = []string{
	fieldJa4ssh,
	fieldFlow,
}

var sshMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SSH.String()),
		Help: Type_NC_SSH.String() + " audit records",
	},
	fieldsSSHMetric,
)

func (a *SSH) metricValues() []string {
	return []string{
		a.Ja4Ssh,
		a.Flow,
	}
}

// Inc increments the metrics for the audit record.
func (a *SSH) Inc() {
	sshMetric.WithLabelValues(a.metricValues()...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *SSH) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for SSH and return them here.
// Src returns the source address of the audit record.
func (a *SSH) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for SSH and return them here.
// Dst returns the destination address of the audit record.
func (a *SSH) Dst() string {
	return ""
}

var sshEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *SSH) Encode() []string {
	return filter([]string{
		sshEncoder.Int64(fieldTimestamp, a.Timestamp),
		sshEncoder.String(fieldJa4ssh, a.Ja4Ssh),
		sshEncoder.String(fieldFlow, a.Flow),
		sshEncoder.String(fieldNotes, a.Notes),
		sshEncoder.String(fieldJa4sshSessionType, a.Ja4SshSessionType),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *SSH) Analyze() {

}

// NetcapType returns the type of the current audit record
func (a *SSH) NetcapType() Type {
	return Type_NC_SSH
}
