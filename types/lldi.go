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
	fieldPortDescription = "PortDescription"
	fieldSysDescription  = "SysDescription"
	fieldSysCapabilities = "SysCapabilities"
	fieldMgmtAddress     = "MgmtAddress"
	fieldOrgTLVs         = "OrgTLVs"
)

var fieldsLLDI = []string{
	fieldTimestamp,
	fieldPortDescription,
	fieldSysName,
	fieldSysDescription,
	fieldSysCapabilities,
	fieldMgmtAddress,
	fieldOrgTLVs,
	fieldUnknown,
}

// CSVHeader returns the CSV header for the audit record.
func (l *LinkLayerDiscoveryInfo) CSVHeader() []string {
	return filter(fieldsLLDI)
}

// CSVRecord returns the CSV record for the audit record.
func (l *LinkLayerDiscoveryInfo) CSVRecord() []string {
	var (
		tlvs   = make([]string, len(l.OrgTLVs))
		values = make([]string, len(l.Unknown))
	)
	for i, v := range l.OrgTLVs {
		tlvs[i] = v.toString()
	}
	for i, v := range l.Unknown {
		values[i] = v.toString()
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		l.PortDescription,            // string
		l.SysName,                    // string
		l.SysDescription,             // string
		l.SysCapabilities.toString(), // *LLDPSysCapabilities
		l.MgmtAddress.toString(),     // *LLDPMgmtAddress
		strings.Join(tlvs, ""),       // []*LLDPOrgSpecificTLV
		strings.Join(values, ""),     // []*LinkLayerDiscoveryValue
	})
}

// Time returns the timestamp associated with the audit record.
func (l *LinkLayerDiscoveryInfo) Time() int64 {
	return l.Timestamp
}

func (lldsc *LLDPSysCapabilities) toString() string {
	return lldsc.SystemCap.toString() + lldsc.EnabledCap.toString()
}

func (lldma *LLDPMgmtAddress) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(lldma.Subtype)) // int32   // byte
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(lldma.Address)) // bytes
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(lldma.InterfaceSubtype)) // int32   // byte
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatUint(uint64(lldma.InterfaceNumber), 10)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(lldma.OID) // string
	b.WriteString(StructureEnd)
	return b.String()
}

func (lldst *LLDPOrgSpecificTLV) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(strconv.FormatUint(uint64(lldst.OUI), 10))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(lldst.SubType))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(lldst.Info))
	b.WriteString(StructureEnd)
	return b.String()
}

func (lldv *LinkLayerDiscoveryValue) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(lldv.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(lldv.Length))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(lldv.Value))
	b.WriteString(StructureEnd)
	return b.String()
}

func (c *LLDPCapabilities) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(strconv.FormatBool(c.Other))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.Repeater))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.Bridge))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.WLANAP))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.Router))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.Phone))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.DocSis))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.StationOnly))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.CVLAN))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.SVLAN))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.TMPR))
	b.WriteString(StructureEnd)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (l *LinkLayerDiscoveryInfo) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	l.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(l)
}

var lldiMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LinkLayerDiscoveryInfo.String()),
		Help: Type_NC_LinkLayerDiscoveryInfo.String() + " audit records",
	},
	fieldsLLDI[1:],
)

// Inc increments the metrics for the audit record.
func (l *LinkLayerDiscoveryInfo) Inc() {
	lldiMetric.WithLabelValues(l.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (l *LinkLayerDiscoveryInfo) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (l *LinkLayerDiscoveryInfo) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (l *LinkLayerDiscoveryInfo) Dst() string {
	return ""
}

var lddiEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (l *LinkLayerDiscoveryInfo) Encode() []string {
	var (
		tlvs   = make([]string, len(l.OrgTLVs))
		values = make([]string, len(l.Unknown))
	)
	for i, v := range l.OrgTLVs {
		tlvs[i] = v.toString()
	}
	for i, v := range l.Unknown {
		values[i] = v.toString()
	}
	return filter([]string{
		lddiEncoder.Int64(fieldTimestamp, l.Timestamp),
		lddiEncoder.String(fieldPortDescription, l.PortDescription),            // string
		lddiEncoder.String(fieldSysName, l.SysName),                            // string
		lddiEncoder.String(fieldSysDescription, l.SysDescription),              // string
		lddiEncoder.String(fieldSysCapabilities, l.SysCapabilities.toString()), // *LLDPSysCapabilities
		lddiEncoder.String(fieldMgmtAddress, l.MgmtAddress.toString()),         // *LLDPMgmtAddress
		lddiEncoder.String(fieldOrgTLVs, strings.Join(tlvs, "")),               // []*LLDPOrgSpecificTLV
		lddiEncoder.String(fieldValues, strings.Join(values, "")),              // []*LinkLayerDiscoveryValue
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (l *LinkLayerDiscoveryInfo) Analyze() {}

// NetcapType returns the type of the current audit record
func (l *LinkLayerDiscoveryInfo) NetcapType() Type {
	return Type_NC_LinkLayerDiscoveryInfo
}
