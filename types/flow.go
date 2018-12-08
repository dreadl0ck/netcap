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

func (f Flow) CSVHeader() []string {
	return filter([]string{
		"TimestampFirst",
		"LinkProto",
		"NetworkProto",
		"TransportProto",
		"ApplicationProto",
		"SrcMAC",
		"DstMAC",
		"SrcIP",
		"SrcPort",
		"DstIP",
		"DstPort",
		"Size",
		"AppPayloadSize",
		"NumPackets",
		"UID",
		"Duration",
		"TimestampLast",
	})
}

func (f Flow) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(f.TimestampFirst),
		f.LinkProto,
		f.NetworkProto,
		f.TransportProto,
		f.ApplicationProto,
		f.SrcMAC,
		f.DstMAC,
		f.SrcIP,
		f.SrcPort,
		f.DstIP,
		f.DstPort,
		formatInt32(f.Size),
		formatInt32(f.AppPayloadSize),
		formatInt32(f.NumPackets),
		f.UID,
		formatInt64(f.Duration),
		formatTimestamp(f.TimestampLast),
	})
}

func (f Flow) NetcapTimestamp() string {
	return f.TimestampFirst
}
