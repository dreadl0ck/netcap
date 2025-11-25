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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldDNP3Control            = "Control"
	fieldDNP3IsMaster           = "IsMaster"
	fieldDNP3Destination        = "Destination"
	fieldDNP3Source             = "Source"
	fieldDNP3FunctionCodeName   = "FunctionCodeName"
	fieldDNP3ConfirmRequired    = "ConfirmRequired"
	fieldDNP3Unsolicited        = "Unsolicited"
	fieldDNP3IINBroadcast       = "IINBroadcast"
	fieldDNP3IINNeedTime        = "IINNeedTime"
	fieldDNP3IINDeviceTrouble   = "IINDeviceTrouble"
	fieldDNP3IINDeviceRestart   = "IINDeviceRestart"
	fieldDNP3IsCriticalFunction = "IsCriticalFunction"
	fieldDNP3IsConfigChange     = "IsConfigChange"
	fieldDNP3IsAuthentication   = "IsAuthentication"
	fieldDNP3IsRequest          = "IsRequest"
	fieldDNP3SecurityContext    = "SecurityContext"
)

var fieldsDNP3 = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldLength,
	fieldDNP3Control,
	fieldDNP3IsMaster,
	fieldDNP3IsRequest,
	fieldDNP3Destination,
	fieldDNP3Source,
	fieldFunctionCode,
	fieldDNP3FunctionCodeName,
	fieldDNP3ConfirmRequired,
	fieldDNP3Unsolicited,
	fieldDNP3IINBroadcast,
	fieldDNP3IINNeedTime,
	fieldDNP3IINDeviceTrouble,
	fieldDNP3IINDeviceRestart,
	fieldDNP3IsCriticalFunction,
	fieldDNP3IsConfigChange,
	fieldDNP3IsAuthentication,
	fieldDNP3SecurityContext,
}

// CSVHeader returns the CSV header for the audit record.
func (d *DNP3) CSVHeader() []string {
	return filter(fieldsDNP3)
}

// CSVRecord returns the CSV record for the audit record.
func (d *DNP3) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		d.SrcIP,
		d.DstIP,
		formatInt32(d.SrcPort),
		formatInt32(d.DstPort),
		formatInt32(d.Length),
		formatInt32(d.Control),
		strconv.FormatBool(d.IsMaster),
		strconv.FormatBool(d.IsRequest),
		formatInt32(d.Destination),
		formatInt32(d.Source),
		formatInt32(d.FunctionCode),
		d.FunctionCodeName,
		strconv.FormatBool(d.ConfirmRequired),
		strconv.FormatBool(d.Unsolicited),
		strconv.FormatBool(d.IINBroadcast),
		strconv.FormatBool(d.IINNeedTime),
		strconv.FormatBool(d.IINDeviceTrouble),
		strconv.FormatBool(d.IINDeviceRestart),
		strconv.FormatBool(d.IsCriticalFunction),
		strconv.FormatBool(d.IsConfigChange),
		strconv.FormatBool(d.IsAuthentication),
		d.SecurityContext,
	})
}

// Time returns the timestamp associated with the audit record.
func (d *DNP3) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *DNP3) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var dnp3Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DNP3.String()),
		Help: Type_NC_DNP3.String() + " audit records",
	},
	fieldsDNP3[1:],
)

// Inc increments the metrics for the audit record.
func (d *DNP3) Inc() {
	dnp3Metric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DNP3) SetPacketContext(ctx *PacketContext) {
	d.SrcIP = ctx.SrcIP
	d.DstIP = ctx.DstIP
	d.SrcPort = ctx.SrcPort
	d.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (d *DNP3) Src() string {
	return d.SrcIP
}

// Dst returns the destination address of the audit record.
func (d *DNP3) Dst() string {
	return d.DstIP
}

var dnp3Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *DNP3) Encode() []string {
	return filter([]string{
		dnp3Encoder.Int64(fieldTimestamp, d.Timestamp),
		dnp3Encoder.String(fieldSrcIP, d.SrcIP),
		dnp3Encoder.String(fieldDstIP, d.DstIP),
		dnp3Encoder.Int32(fieldSrcPort, d.SrcPort),
		dnp3Encoder.Int32(fieldDstPort, d.DstPort),
		dnp3Encoder.Int32(fieldLength, d.Length),
		dnp3Encoder.Int32(fieldDNP3Control, d.Control),
		dnp3Encoder.Bool(d.IsMaster),
		dnp3Encoder.Bool(d.IsRequest),
		dnp3Encoder.Int32(fieldDNP3Destination, d.Destination),
		dnp3Encoder.Int32(fieldDNP3Source, d.Source),
		dnp3Encoder.Int32(fieldFunctionCode, d.FunctionCode),
		dnp3Encoder.String(fieldDNP3FunctionCodeName, d.FunctionCodeName),
		dnp3Encoder.Bool(d.ConfirmRequired),
		dnp3Encoder.Bool(d.Unsolicited),
		dnp3Encoder.Bool(d.IINBroadcast),
		dnp3Encoder.Bool(d.IINNeedTime),
		dnp3Encoder.Bool(d.IINDeviceTrouble),
		dnp3Encoder.Bool(d.IINDeviceRestart),
		dnp3Encoder.Bool(d.IsCriticalFunction),
		dnp3Encoder.Bool(d.IsConfigChange),
		dnp3Encoder.Bool(d.IsAuthentication),
		dnp3Encoder.String(fieldDNP3SecurityContext, d.SecurityContext),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *DNP3) Analyze() {}

// NetcapType returns the type of the current audit record
func (d *DNP3) NetcapType() Type {
	return Type_NC_DNP3
}
