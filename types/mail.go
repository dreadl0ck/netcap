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
)

var fieldsMail = []string{
	"Timestamp",       // int64
	"ReturnPath",      // string
	"From",            // string
	"To",              // string
	"CC",              // string
	"Subject",         // string
	"Date",            // string
	"MessageID",       // string
	"References",      // string
	"InReplyTo",       // string
	"ContentLanguage", // string
	"HasAttachments",  // bool
	"XOriginatingIP",  // string
	"ContentType",     // string
	"EnvelopeTo",      // string
	//"Body",            // []*MailPart
	"ClientIP",        // string
	"ServerIP",        // string
	"ID",              // string
}

// CSVHeader returns the CSV header for the audit record.
func (d *Mail) CSVHeader() []string {
	return filter(fieldsMail)
}

// CSVRecord returns the CSV record for the audit record.
func (d *Mail) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		d.ReturnPath,      // string
		d.From,            // string
		d.To,              // string
		d.CC,              // string
		d.Subject,         // string
		d.Date,            // string
		d.MessageID,       // string
		d.References,      // string
		d.InReplyTo,       // string
		d.ContentLanguage, // string
		strconv.FormatBool(d.HasAttachments),  // bool
		d.XOriginatingIP,  // string
		d.ContentType,     // string
		d.EnvelopeTo,      // string
		//d.Body,            // []*MailPart
		formatInt64(d.Timestamp),       // int64
		d.ClientIP,        // string
		d.ServerIP,        // string
		d.ID,              // string
	})
}

// Time returns the timestamp associated with the audit record.
func (d *Mail) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *Mail) JSON() (string, error) {
	//	d.Timestamp = utils.TimeToUnixMilli(d.Timestamp)

	return jsonMarshaler.MarshalToString(d)
}

// Inc increments the metrics for the audit record.
func (d *Mail) Inc() {}

// SetPacketContext sets the associated packet context for the audit record.
func (d *Mail) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (d *Mail) Src() string {
	return d.ClientIP

}

// Dst returns the destination address of the audit record.
func (d *Mail) Dst() string {
	return d.ServerIP
}
