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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsUSBRequestBlockSetup = []string{
	"Timestamp",
	"RequestType", // int32
	"Request",     // int32
	"Value",       // int32
	"Index",       // int32
	"Length",      // int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *USBRequestBlockSetup) CSVHeader() []string {
	return filter(fieldsUSBRequestBlockSetup)
}

// CSVRecord returns the CSV record for the audit record.
func (a *USBRequestBlockSetup) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.RequestType), // int32
		formatInt32(a.Request),     // int32
		formatInt32(a.Value),       // int32
		formatInt32(a.Index),       // int32
		formatInt32(a.Length),      // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *USBRequestBlockSetup) Time() string {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *USBRequestBlockSetup) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var usbRequestBlockSetupMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_USBRequestBlockSetup.String()),
		Help: Type_NC_USBRequestBlockSetup.String() + " audit records",
	},
	fieldsUSBRequestBlockSetup[1:],
)

func init() {
	prometheus.MustRegister(usbRequestBlockSetupMetric)
}

// Inc increments the metrics for the audit record.
func (a *USBRequestBlockSetup) Inc() {
	usbRequestBlockSetupMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *USBRequestBlockSetup) SetPacketContext(*PacketContext) {}

// Src TODO return source DeviceAddress?
// Src returns the source address of the audit record.
func (a *USBRequestBlockSetup) Src() string {
	return ""
}

// Dst TODO return destination DeviceAddress?
// Dst returns the destination address of the audit record.
func (a *USBRequestBlockSetup) Dst() string {
	return ""
}
