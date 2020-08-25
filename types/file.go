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

var fieldsFile = []string{
	"Timestamp",
	"Name",
	"Length",
	"Hash",
	"Location",
	"Ident",
	"Source",
	"ContentType",
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

// CSVHeader returns the CSV header for the audit record.
func (a *File) CSVHeader() []string {
	return filter(fieldsFile)
}

// CSVRecord returns the CSV record for the audit record.
func (a *File) CSVRecord() []string {

	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Name,
		formatInt64(a.Length),
		a.Hash,
		a.Location,
		a.Ident,
		a.Source,
		a.ContentType,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *File) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *File) JSON() (string, error) {
	//	// a.Timestamp = utils.TimeToUnixMilli(a.Timestamp)
	return jsonMarshaler.MarshalToString(a)
}

var fileMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_File.String()),
		Help: Type_NC_File.String() + " audit records",
	},
	fieldsARP[1:],
)

// Inc increments the metrics for the audit record.
func (a *File) Inc() {
	fileMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *File) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *File) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *File) Dst() string {
	return a.DstIP
}
