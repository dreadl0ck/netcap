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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldSTPProtocolID       = "ProtocolID"
	fieldSTPVersionName      = "VersionName"
	fieldSTPTypeName         = "TypeName"
	fieldSTPTC               = "TC"
	fieldSTPTCA              = "TCA"
	fieldSTPRootID           = "RootID"
	fieldSTPCost             = "Cost"
	fieldSTPBridgeID         = "BridgeID"
	fieldSTPPortID           = "PortID"
	fieldSTPMessageAge       = "MessageAge"
	fieldSTPMaxAge           = "MaxAge"
	fieldSTPHelloTime        = "HelloTime"
	fieldSTPForwardDelay     = "ForwardDelay"
	fieldSTPIsTopologyChange = "IsTopologyChange"
	fieldSTPIsConfigBPDU     = "IsConfigBPDU"
	fieldSTPIsTCN            = "IsTCN"
	fieldSTPIsRootBridge     = "IsRootBridge"
	fieldSTPHasZeroPriority  = "HasZeroPriority"
)

var fieldsSTP = []string{
	fieldTimestamp,
	fieldSTPProtocolID,       // int32
	fieldVersion,             // int32
	fieldSTPVersionName,      // string
	fieldType,                // int32
	fieldSTPTypeName,         // string
	fieldSTPTC,               // bool
	fieldSTPTCA,              // bool
	fieldSTPRootID,           // *STPSwitchID
	fieldSTPCost,             // uint32
	fieldSTPBridgeID,         // *STPSwitchID
	fieldSTPPortID,           // int32
	fieldSTPMessageAge,       // int32
	fieldSTPMaxAge,           // int32
	fieldSTPHelloTime,        // int32
	fieldSTPForwardDelay,     // int32
	fieldSTPIsTopologyChange, // bool
	fieldSTPIsConfigBPDU,     // bool
	fieldSTPIsTCN,            // bool
	fieldSTPIsRootBridge,     // bool
	fieldSTPHasZeroPriority,  // bool
}

// CSVHeader returns the CSV header for the audit record.
func (s *STP) CSVHeader() []string {
	return filter(fieldsSTP)
}

func (s *STPSwitchID) toString() string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(s.Priority))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(s.SysID))
	b.WriteString(FieldSeparator)
	b.WriteString(s.HwAddr)
	b.WriteString(StructureEnd)
	return b.String()
}

// CSVRecord returns the CSV record for the audit record.
func (s *STP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		formatInt32(s.ProtocolID),              // int32
		formatInt32(s.Version),                 // int32
		s.VersionName,                          // string
		formatInt32(s.Type),                    // int32
		s.TypeName,                             // string
		strconv.FormatBool(s.TC),               // bool
		strconv.FormatBool(s.TCA),              // bool
		s.RootID.toString(),                    // *STPSwitchID
		formatUint32(s.Cost),                   // uint32
		s.BridgeID.toString(),                  // *STPSwitchID
		formatInt32(s.PortID),                  // int32
		formatInt32(s.MessageAge),              // int32
		formatInt32(s.MaxAge),                  // int32
		formatInt32(s.HelloTime),               // int32
		formatInt32(s.ForwardDelay),            // int32
		strconv.FormatBool(s.IsTopologyChange), // bool
		strconv.FormatBool(s.IsConfigBPDU),     // bool
		strconv.FormatBool(s.IsTCN),            // bool
		strconv.FormatBool(s.IsRootBridge),     // bool
		strconv.FormatBool(s.HasZeroPriority),  // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (s *STP) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (s *STP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	s.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(s)
}

var stpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_STP.String()),
		Help: Type_NC_STP.String() + " audit records",
	},
	fieldsSTP[1:],
)

// Inc increments the metrics for the audit record.
func (s *STP) Inc() {
	stpMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *STP) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (s *STP) Src() string {
	if s.BridgeID != nil {
		return s.BridgeID.HwAddr
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (s *STP) Dst() string {
	if s.RootID != nil {
		return s.RootID.HwAddr
	}
	return ""
}

var stpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (s *STP) Encode() []string {
	return filter([]string{
		stpEncoder.Int64(fieldTimestamp, s.Timestamp),
		stpEncoder.Int32(fieldSTPProtocolID, s.ProtocolID),         // int32
		stpEncoder.Int32(fieldVersion, s.Version),                  // int32
		stpEncoder.String(fieldSTPVersionName, s.VersionName),      // string
		stpEncoder.Int32(fieldType, s.Type),                        // int32
		stpEncoder.String(fieldSTPTypeName, s.TypeName),            // string
		stpEncoder.Bool(s.TC),                                      // bool
		stpEncoder.Bool(s.TCA),                                     // bool
		stpEncoder.String(fieldSTPRootID, s.RootID.toString()),     // *STPSwitchID
		stpEncoder.Uint32(fieldSTPCost, s.Cost),                    // uint32
		stpEncoder.String(fieldSTPBridgeID, s.BridgeID.toString()), // *STPSwitchID
		stpEncoder.Int32(fieldSTPPortID, s.PortID),                 // int32
		stpEncoder.Int32(fieldSTPMessageAge, s.MessageAge),         // int32
		stpEncoder.Int32(fieldSTPMaxAge, s.MaxAge),                 // int32
		stpEncoder.Int32(fieldSTPHelloTime, s.HelloTime),           // int32
		stpEncoder.Int32(fieldSTPForwardDelay, s.ForwardDelay),     // int32
		stpEncoder.Bool(s.IsTopologyChange),                        // bool
		stpEncoder.Bool(s.IsConfigBPDU),                            // bool
		stpEncoder.Bool(s.IsTCN),                                   // bool
		stpEncoder.Bool(s.IsRootBridge),                            // bool
		stpEncoder.Bool(s.HasZeroPriority),                         // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *STP) Analyze() {}

// NetcapType returns the type of the current audit record
func (s *STP) NetcapType() Type {
	return Type_NC_STP
}
