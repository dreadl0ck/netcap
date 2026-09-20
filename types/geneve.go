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
	fieldOptionsLength  = "OptionsLength"
	fieldOAMPacket      = "OAMPacket"
	fieldCriticalOption = "CriticalOption"
	fieldVNI            = "VNI"
)

var fieldsGeneve = []string{
	fieldTimestamp,
	fieldVersion,        // int32
	fieldOptionsLength,  // int32
	fieldOAMPacket,      // bool
	fieldCriticalOption, // bool
	fieldProtocol,       // int32
	fieldVNI,            // uint32
	fieldOptions,        // []*GeneveOption
}

// CSVHeader returns the CSV header for the audit record.
func (i *Geneve) CSVHeader() []string {
	return filter(fieldsGeneve)
}

// CSVRecord returns the CSV record for the audit record.
func (i *Geneve) CSVRecord() []string {
	opts := make([]string, 0, len(i.Options))
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Version),               // int32
		formatInt32(i.OptionsLength),         // int32
		strconv.FormatBool(i.OAMPacket),      // bool
		strconv.FormatBool(i.CriticalOption), // bool
		formatInt32(i.Protocol),              // int32
		formatUint32(i.VNI),                  // uint32
		strings.Join(opts, ""),               // []*GeneveOption
	})
}

// Time returns the timestamp associated with the audit record.
func (i *Geneve) Time() int64 {
	return i.Timestamp
}

func (i *GeneveOption) toString() string {
	if i == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(i.Class))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.Flags))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.Length))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(i.Data))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (i *Geneve) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var geneveMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Geneve.String()),
		Help: Type_NC_Geneve.String() + " audit records",
	},
	fieldsGeneve[1:],
)

// Inc increments the metrics for the audit record.
func (i *Geneve) Inc() {
	geneveMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *Geneve) SetPacketContext(_ *PacketContext) {}

// Src returns the source address of the audit record.
func (i *Geneve) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (i *Geneve) Dst() string {
	return ""
}

var geneveEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *Geneve) Encode() []string {

	opts := make([]string, 0, len(i.Options))
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		geneveEncoder.Int64(fieldTimestamp, i.Timestamp),
		geneveEncoder.Int32(fieldVersion, i.Version),               // int32
		geneveEncoder.Int32(fieldOptionsLength, i.OptionsLength),   // int32
		geneveEncoder.Bool(i.OAMPacket),                            // bool
		geneveEncoder.Bool(i.CriticalOption),                       // bool
		geneveEncoder.Int32(fieldProtocol, i.Protocol),             // int32
		geneveEncoder.Uint32(fieldVNI, i.VNI),                      // uint32
		geneveEncoder.String(fieldOptions, strings.Join(opts, "")), // []*GeneveOption
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *Geneve) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *Geneve) NetcapType() Type {
	return Type_NC_Geneve
}
