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
	fieldProto          = "Proto"
	fieldDurationID     = "DurationID"
	fieldAddress1       = "Address1"
	fieldAddress2       = "Address2"
	fieldAddress3       = "Address3"
	fieldAddress4       = "Address4"
	fieldSequenceNumber = "SequenceNumber"
	fieldFragmentNumber = "FragmentNumber"
	fieldQOS            = "QOS"
	fieldHTControl      = "HTControl"
)

var fieldsDot11 = []string{
	fieldTimestamp,
	fieldType,           // int32
	fieldProto,          // int32
	fieldFlags,          // int32
	fieldDurationID,     // int32
	fieldAddress1,       // string
	fieldAddress2,       // string
	fieldAddress3,       // string
	fieldAddress4,       // string
	fieldSequenceNumber, // int32
	fieldFragmentNumber, // int32
	fieldChecksum,       // uint32
	fieldQOS,            // *Dot11QOS
	fieldHTControl,      // *Dot11HTControl
}

// CSVHeader returns the CSV header for the audit record.
func (d *Dot11) CSVHeader() []string {
	return filter(fieldsDot11)
}

// CSVRecord returns the CSV record for the audit record.
func (d *Dot11) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatInt32(d.Type),           // int32
		formatInt32(d.Proto),          // int32
		formatInt32(d.Flags),          // int32
		formatInt32(d.DurationID),     // int32
		d.Address1,                    // string
		d.Address2,                    // string
		d.Address3,                    // string
		d.Address4,                    // string
		formatInt32(d.SequenceNumber), // int32
		formatInt32(d.FragmentNumber), // int32
		formatUint32(d.Checksum),      // uint32
		d.QOS.toString(),              // *Dot11QOS
		d.HTControl.toString(),        // *Dot11HTControl
	})
}

// Time returns the timestamp associated with the audit record.
func (d *Dot11) Time() int64 {
	return d.Timestamp
}

func (d Dot11QOS) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(d.TID))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.EOSP))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.AckPolicy))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.TXOP))
	b.WriteString(StructureEnd)
	return b.String()
}

func (d Dot11HTControl) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(strconv.FormatBool(d.ACConstraint))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.RDGMorePPDU))
	b.WriteString(FieldSeparator)
	b.WriteString(d.VHT.toString())
	b.WriteString(FieldSeparator)
	b.WriteString(d.HT.toString())
	b.WriteString(StructureEnd)
	return b.String()
}

func (d *Dot11HTControlVHT) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(strconv.FormatBool(d.MRQ))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.UnsolicitedMFB))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.MSI))
	b.WriteString(FieldSeparator)
	b.WriteString(d.MFB.toString())
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.CompressedMSI))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.STBCIndication))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.MFSI))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.GID))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.CodingType))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.FbTXBeamformed))
	b.WriteString(StructureEnd)
	return b.String()
}

func (d *Dot11HTControlMFB) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(d.NumSTS))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.VHTMCS))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.BW))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.SNR))
	b.WriteString(StructureEnd)
	return b.String()
}

func (d *Dot11HTControlHT) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(d.LinkAdapationControl.toString())
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.CalibrationPosition))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.CalibrationSequence))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.CSISteering))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.NDPAnnouncement))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.DEI))
	b.WriteString(StructureEnd)
	return b.String()
}

func (d *Dot11LinkAdapationControl) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(strconv.FormatBool(d.TRQ))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(d.MRQ))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.MSI))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.MFSI))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.MFB))
	b.WriteString(FieldSeparator)
	b.WriteString(d.ASEL.toString())
	b.WriteString(StructureEnd)
	return b.String()
}

func (d *Dot11ASEL) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(d.Command))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.Data))
	b.WriteString(StructureEnd)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (d *Dot11) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var dot11Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Dot11.String()),
		Help: Type_NC_Dot11.String() + " audit records",
	},
	fieldsDot11[1:],
)

// Inc increments the metrics for the audit record.
func (d *Dot11) Inc() {
	dot11Metric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *Dot11) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (d *Dot11) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (d *Dot11) Dst() string {
	return ""
}

var dot11Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *Dot11) Encode() []string {
	return filter([]string{
		dot11Encoder.Int64(fieldTimestamp, d.Timestamp),
		dot11Encoder.Int32(fieldType, d.Type),                     // int32
		dot11Encoder.Int32(fieldProto, d.Proto),                   // int32
		dot11Encoder.Int32(fieldFlags, d.Flags),                   // int32
		dot11Encoder.Int32(fieldDurationID, d.DurationID),         // int32
		dot11Encoder.String(fieldAddress1, d.Address1),            // string
		dot11Encoder.String(fieldAddress2, d.Address2),            // string
		dot11Encoder.String(fieldAddress3, d.Address3),            // string
		dot11Encoder.String(fieldAddress4, d.Address4),            // string
		dot11Encoder.Int32(fieldSequenceNumber, d.SequenceNumber), // int32
		dot11Encoder.Int32(fieldFragmentNumber, d.FragmentNumber), // int32
		dot11Encoder.Uint32(fieldChecksum, d.Checksum),            // uint32
		// TODO: flatten
		dot11Encoder.String(fieldQOS, d.QOS.toString()),             // *Dot11QOS
		dot11Encoder.String(fieldHTControl, d.HTControl.toString()), // *Dot11HTControl
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *Dot11) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *Dot11) NetcapType() Type {
	return Type_NC_Dot11
}
