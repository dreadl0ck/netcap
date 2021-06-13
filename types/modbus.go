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
	"encoding/hex"
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldProtocolID   = "ProtocolID"
	fieldUnitID       = "UnitID"
	fieldPayload      = "Payload"
	fieldException    = "Exception"
	fieldFunctionCode = "FunctionCode"
)

var fieldsModbus = []string{
	fieldTimestamp,
	fieldTransactionID, // int32
	fieldProtocolID,    // int32
	fieldLength,        // int32
	fieldUnitID,        // int32
	//fieldPayload,       // []byte
	fieldException,    // bool
	fieldFunctionCode, // int32
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *Modbus) CSVHeader() []string {
	return filter(fieldsModbus)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Modbus) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.TransactionID), // int32
		formatInt32(a.ProtocolID),    // int32
		formatInt32(a.Length),        // int32
		formatInt32(a.UnitID),        // int32
		hex.EncodeToString(a.Payload),
		strconv.FormatBool(a.Exception),
		formatInt32(a.FunctionCode),
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Modbus) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Modbus) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var modbusTCPMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Modbus.String()),
		Help: Type_NC_Modbus.String() + " audit records",
	},
	fieldsModbus[1:],
)

// Inc increments the metrics for the audit record.
func (a *Modbus) Inc() {
	modbusTCPMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Modbus) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
	a.SrcPort = ctx.SrcPort
	a.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (a *Modbus) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *Modbus) Dst() string {
	return a.DstIP
}

var modbusEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Modbus) Encode() []string {
	return filter([]string{
		modbusEncoder.Int64(fieldTimestamp, a.Timestamp),
		modbusEncoder.Int32(fieldTransactionID, a.TransactionID), // int32
		modbusEncoder.Int32(fieldProtocolID, a.ProtocolID),       // int32
		modbusEncoder.Int32(fieldLength, a.Length),               // int32
		modbusEncoder.Int32(fieldUnitID, a.UnitID),               // int32
		//hex.EncodeToString(a.Payload),
		modbusEncoder.Bool(a.Exception),
		modbusEncoder.Int32(fieldFunctionCode, a.FunctionCode),
		modbusEncoder.String(fieldSrcIP, a.SrcIP),
		modbusEncoder.String(fieldDstIP, a.DstIP),
		modbusEncoder.Int32(fieldSrcPort, a.SrcPort),
		modbusEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Modbus) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *Modbus) NetcapType() Type {
	return Type_NC_Modbus
}
