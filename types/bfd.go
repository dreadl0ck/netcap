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
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldVersion                   = "Version"
	fieldDiagnostic                = "Diagnostic"
	fieldState                     = "State"
	fieldPoll                      = "Poll"
	fieldFinal                     = "Final"
	fieldControlPlaneIndependent   = "ControlPlaneIndependent"
	fieldAuthPresent               = "AuthPresent"
	fieldDemand                    = "Demand"
	fieldMultipoint                = "Multipoint"
	fieldDetectMultiplier          = "DetectMultiplier"
	fieldMyDiscriminator           = "MyDiscriminator"
	fieldYourDiscriminator         = "YourDiscriminator"
	fieldDesiredMinTxInterval      = "DesiredMinTxInterval"
	fieldRequiredMinRxInterval     = "RequiredMinRxInterval"
	fieldRequiredMinEchoRxInterval = "RequiredMinEchoRxInterval"
	fieldAuthHeader                = "AuthHeader"
)

var fieldsBFD = []string{
	fieldTimestamp,
	fieldVersion,
	fieldDiagnostic,
	fieldState,
	fieldPoll,
	fieldFinal,
	fieldControlPlaneIndependent,
	fieldAuthPresent,
	fieldDemand,
	fieldMultipoint,
	fieldDetectMultiplier,
	fieldMyDiscriminator,
	fieldYourDiscriminator,
	fieldDesiredMinTxInterval,
	fieldRequiredMinRxInterval,
	fieldRequiredMinEchoRxInterval,
	fieldAuthHeader,
}

// CSVHeader returns the CSV header for the audit record.
func (b *BFD) CSVHeader() []string {
	return filter(fieldsBFD)
}

// CSVRecord returns the CSV record for the audit record.
func (b *BFD) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(b.Timestamp),
		formatInt32(b.Version),                        // int32
		formatInt32(b.Diagnostic),                     // int32
		formatInt32(b.State),                          // int32
		strconv.FormatBool(b.Poll),                    // bool
		strconv.FormatBool(b.Final),                   // bool
		strconv.FormatBool(b.ControlPlaneIndependent), // bool
		strconv.FormatBool(b.AuthPresent),             // bool
		strconv.FormatBool(b.Demand),                  // bool
		strconv.FormatBool(b.Multipoint),              // bool
		formatInt32(b.DetectMultiplier),               // int32
		formatInt32(b.MyDiscriminator),                // int32
		formatInt32(b.YourDiscriminator),              // int32
		formatInt32(b.DesiredMinTxInterval),           // int32
		formatInt32(b.RequiredMinRxInterval),          // int32
		formatInt32(b.RequiredMinEchoRxInterval),      // int32
		b.AuthHeader.getString(),                      // *BFDAuthHeader
	})
}

// Time returns the timestamp associated with the audit record.
func (b *BFD) Time() int64 {
	return b.Timestamp
}

func (bah *BFDAuthHeader) getString() string {
	// BFD packets without authentication carry no auth header.
	if bah == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(bah.AuthType))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(bah.KeyID))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(bah.SequenceNumber))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(bah.Data))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (b *BFD) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	b.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(b)
}

var bfdMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_BFD.String()),
		Help: Type_NC_BFD.String() + " audit records",
	},
	fieldsBFD[1:],
)

// Inc increments the metrics for the audit record.
func (b *BFD) Inc() {
	bfdMetric.WithLabelValues(b.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (b *BFD) SetPacketContext(_ *PacketContext) {}

// Src returns the source address of the audit record.
func (b *BFD) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (b *BFD) Dst() string {
	return ""
}

var bfdEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (b *BFD) Encode() []string {
	return filter([]string{
		bfdEncoder.Int64(fieldTimestamp, b.Timestamp),
		bfdEncoder.Int32(fieldVersion, b.Version),                                     // int32
		bfdEncoder.Int32(fieldDiagnostic, b.Diagnostic),                               // int32
		bfdEncoder.Int32(fieldState, b.State),                                         // int32
		bfdEncoder.Bool(b.Poll),                                                       // bool
		bfdEncoder.Bool(b.Final),                                                      // bool
		bfdEncoder.Bool(b.ControlPlaneIndependent),                                    // bool
		bfdEncoder.Bool(b.AuthPresent),                                                // bool
		bfdEncoder.Bool(b.Demand),                                                     // bool
		bfdEncoder.Bool(b.Multipoint),                                                 // bool
		bfdEncoder.Int32(fieldDetectMultiplier, b.DetectMultiplier),                   // int32
		bfdEncoder.Int32(fieldMyDiscriminator, b.MyDiscriminator),                     // int32
		bfdEncoder.Int32(fieldYourDiscriminator, b.YourDiscriminator),                 // int32
		bfdEncoder.Int32(fieldDesiredMinTxInterval, b.DesiredMinTxInterval),           // int32
		bfdEncoder.Int32(fieldRequiredMinRxInterval, b.RequiredMinRxInterval),         // int32
		bfdEncoder.Int32(fieldRequiredMinEchoRxInterval, b.RequiredMinEchoRxInterval), // int32

		// TODO: flatten as top level fields? also for CSV!
		// bfdEncoder.Int32(b.AuthHeader.getString()),                      // *BFDAuthHeader
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (b *BFD) Analyze() {
}

// NetcapType returns the type of the current audit record
func (b *BFD) NetcapType() Type {
	return Type_NC_BFD
}
