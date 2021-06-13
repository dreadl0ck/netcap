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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldEventType              = "EventType"
	fieldTransferType           = "TransferType"
	fieldDirection              = "Direction"
	fieldEndpointNumber         = "EndpointNumber"
	fieldDeviceAddress          = "DeviceAddress"
	fieldBusID                  = "BusID"
	fieldTimestampSec           = "TimestampSec"
	fieldTimestampUsec          = "TimestampUsec"
	fieldSetup                  = "Setup"
	fieldUrbLength              = "UrbLength"
	fieldUrbDataLength          = "UrbDataLength"
	fieldUrbInterval            = "UrbInterval"
	fieldUrbStartFrame          = "UrbStartFrame"
	fieldUrbCopyOfTransferFlags = "UrbCopyOfTransferFlags"
	fieldIsoNumDesc             = "IsoNumDesc"
)

var fieldsUSB = []string{
	fieldTimestamp,
	fieldID,
	fieldEventType,
	fieldTransferType,
	fieldDirection,
	fieldEndpointNumber,
	fieldDeviceAddress,
	fieldBusID,
	fieldTimestampSec,
	fieldTimestampUsec,
	fieldSetup,
	fieldData,
	fieldStatus,
	fieldUrbLength,
	fieldUrbDataLength,
	fieldUrbInterval,
	fieldUrbStartFrame,
	fieldUrbCopyOfTransferFlags,
	fieldIsoNumDesc,
	//fieldPayload,
}

// CSVHeader returns the CSV header for the audit record.
func (u *USB) CSVHeader() []string {
	return filter(fieldsUSB)
}

// CSVRecord returns the CSV record for the audit record.
func (u *USB) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(u.Timestamp), // string
		formatUint64(u.ID),
		formatInt32(u.EventType),
		formatInt32(u.TransferType),
		formatInt32(u.Direction),
		formatInt32(u.EndpointNumber),
		formatInt32(u.DeviceAddress),
		formatInt32(u.BusID),
		formatInt64(u.TimestampSec),
		formatInt32(u.TimestampUsec),
		strconv.FormatBool(u.Setup),
		strconv.FormatBool(u.Data),
		formatInt32(u.Status),
		formatUint32(u.UrbLength),
		formatUint32(u.UrbDataLength),
		formatUint32(u.UrbInterval),
		formatUint32(u.UrbStartFrame),
		formatUint32(u.UrbCopyOfTransferFlags),
		formatUint32(u.IsoNumDesc),
		//hex.EncodeToString(u.Payload),
	})
}

// Time returns the timestamp associated with the audit record.
func (u *USB) Time() int64 {
	return u.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (u *USB) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	u.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(u)
}

var usbMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_USB.String()),
		Help: Type_NC_USB.String() + " audit records",
	},
	fieldsUSB[1:],
)

// Inc increments the metrics for the audit record.
func (u *USB) Inc() {
	usbMetric.WithLabelValues(u.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (u *USB) SetPacketContext(*PacketContext) {}

// Src TODO return source DeviceAddress?
// Src returns the source address of the audit record.
func (u *USB) Src() string {
	return ""
}

// Dst TODO return destination DeviceAddress?
// Dst returns the destination address of the audit record.
func (u *USB) Dst() string {
	return ""
}

var usbEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (u *USB) Encode() []string {
	return filter([]string{
		usbEncoder.Int64(fieldTimestamp, u.Timestamp), // int64
		usbEncoder.Uint64(fieldID, u.ID),
		usbEncoder.Int32(fieldEventType, u.EventType),
		usbEncoder.Int32(fieldTransferType, u.TransferType),
		usbEncoder.Int32(fieldDirection, u.Direction),
		usbEncoder.Int32(fieldEndpointNumber, u.EndpointNumber),
		usbEncoder.Int32(fieldDeviceAddress, u.DeviceAddress),
		usbEncoder.Int32(fieldBusID, u.BusID),
		usbEncoder.Int64(fieldTimestampSec, u.TimestampSec),
		usbEncoder.Int32(fieldTimestampUsec, u.TimestampUsec),
		usbEncoder.Bool(u.Setup),
		usbEncoder.Bool(u.Data),
		usbEncoder.Int32(fieldStatus, u.Status),
		usbEncoder.Uint32(fieldUrbLength, u.UrbLength),
		usbEncoder.Uint32(fieldUrbDataLength, u.UrbDataLength),
		usbEncoder.Uint32(fieldUrbInterval, u.UrbInterval),
		usbEncoder.Uint32(fieldUrbStartFrame, u.UrbStartFrame),
		usbEncoder.Uint32(fieldUrbCopyOfTransferFlags, u.UrbCopyOfTransferFlags),
		usbEncoder.Uint32(fieldIsoNumDesc, u.IsoNumDesc),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (u *USB) Analyze() {
}

// NetcapType returns the type of the current audit record
func (u *USB) NetcapType() Type {
	return Type_NC_USB
}
