/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
)

func (d Dot11) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Type",           // int32
		"Proto",          // int32
		"Flags",          // int32
		"DurationID",     // int32
		"Address1",       // string
		"Address2",       // string
		"Address3",       // string
		"Address4",       // string
		"SequenceNumber", // int32
		"FragmentNumber", // int32
		"Checksum",       // uint32
		"QOS",            // *Dot11QOS
		"HTControl",      // *Dot11HTControl
	})
}

func (d Dot11) CSVRecord() []string {
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
		d.QOS.ToString(),              // *Dot11QOS
		d.HTControl.ToString(),        // *Dot11HTControl
	})
}

func (d Dot11) NetcapTimestamp() string {
	return d.Timestamp
}

func (d Dot11QOS) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(d.TID))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.EOSP))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.AckPolicy))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.TXOP))
	b.WriteString(end)
	return b.String()
}

func (d Dot11HTControl) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(strconv.FormatBool(d.ACConstraint))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.RDGMorePPDU))
	b.WriteString(sep)
	b.WriteString(d.VHT.ToString())
	b.WriteString(sep)
	b.WriteString(d.HT.ToString())
	b.WriteString(end)
	return b.String()
}

func (d *Dot11HTControlVHT) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(strconv.FormatBool(d.MRQ))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.UnsolicitedMFB))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.MSI))
	b.WriteString(sep)
	b.WriteString(d.MFB.ToString())
	b.WriteString(sep)
	b.WriteString(formatInt32(d.CompressedMSI))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.STBCIndication))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.MFSI))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.GID))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.CodingType))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.FbTXBeamformed))
	b.WriteString(end)
	return b.String()
}

func (d *Dot11HTControlMFB) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(d.NumSTS))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.VHTMCS))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.BW))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.SNR))
	b.WriteString(end)
	return b.String()
}

func (d *Dot11HTControlHT) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(d.LinkAdapationControl.ToString())
	b.WriteString(sep)
	b.WriteString(formatInt32(d.CalibrationPosition))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.CalibrationSequence))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.CSISteering))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.NDPAnnouncement))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.DEI))
	b.WriteString(end)
	return b.String()
}

func (d *Dot11LinkAdapationControl) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(strconv.FormatBool(d.TRQ))
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(d.MRQ))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.MSI))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.MFSI))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.MFB))
	b.WriteString(sep)
	b.WriteString(d.ASEL.ToString())
	b.WriteString(end)
	return b.String()
}

func (d *Dot11ASEL) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(d.Command))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.Data))
	b.WriteString(end)
	return b.String()
}
