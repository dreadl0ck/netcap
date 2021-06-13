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
	"time"
)

const (
	fieldReturnPath      = "ReturnPath"
	fieldFrom            = "From"
	fieldTo              = "To"
	fieldCC              = "CC"
	fieldSubject         = "Subject"
	fieldDate            = "Date"
	fieldMessageID       = "MessageID"
	fieldReferences      = "References"
	fieldInReplyTo       = "InReplyTo"
	fieldContentLanguage = "ContentLanguage"
	fieldHasAttachments  = "HasAttachments"
	fieldXOriginatingIP  = "XOriginatingIP"
	fieldEnvelopeTo      = "EnvelopeTo"
	fieldBody            = "Body"
	fieldServerIP        = "ServerIP"
)

var fieldsMail = []string{
	fieldTimestamp,       // int64
	fieldReturnPath,      // string
	fieldFrom,            // string
	fieldTo,              // string
	fieldCC,              // string
	fieldSubject,         // string
	fieldDate,            // string
	fieldMessageID,       // string
	fieldReferences,      // string
	fieldInReplyTo,       // string
	fieldContentLanguage, // string
	fieldHasAttachments,  // bool
	fieldXOriginatingIP,  // string
	fieldContentType,     // string
	fieldEnvelopeTo,      // string
	//fieldBody,            // []*MailPart
	fieldClientIP, // string
	fieldServerIP, // string
	fieldID,       // string
}

// CSVHeader returns the CSV header for the audit record.
func (d *Mail) CSVHeader() []string {
	return filter(fieldsMail)
}

// CSVRecord returns the CSV record for the audit record.
func (d *Mail) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		d.ReturnPath,                         // string
		d.From,                               // string
		d.To,                                 // string
		d.CC,                                 // string
		d.Subject,                            // string
		d.Date,                               // string
		d.MessageID,                          // string
		d.References,                         // string
		d.InReplyTo,                          // string
		d.ContentLanguage,                    // string
		strconv.FormatBool(d.HasAttachments), // bool
		d.XOriginatingIP,                     // string
		d.ContentType,                        // string
		d.EnvelopeTo,                         // string
		// d.Body,            // []*MailPart
		d.ClientIP, // string
		d.ServerIP, // string
		d.ID,       // string
	})
}

// Time returns the timestamp associated with the audit record.
func (d *Mail) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *Mail) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

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

var mailEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *Mail) Encode() []string {
	return filter([]string{
		mailEncoder.Int64(fieldTimestamp, d.Timestamp),
		mailEncoder.String(fieldReturnPath, d.ReturnPath),           // string
		mailEncoder.String(fieldFrom, d.From),                       // string
		mailEncoder.String(fieldTo, d.To),                           // string
		mailEncoder.String(fieldCC, d.CC),                           // string
		mailEncoder.String(fieldSubject, d.Subject),                 // string
		mailEncoder.String(fieldDate, d.Date),                       // string
		mailEncoder.String(fieldMessageID, d.MessageID),             // string
		mailEncoder.String(fieldReferences, d.References),           // string
		mailEncoder.String(fieldInReplyTo, d.InReplyTo),             // string
		mailEncoder.String(fieldContentLanguage, d.ContentLanguage), // string
		mailEncoder.Bool(d.HasAttachments),                          // bool
		mailEncoder.String(fieldXOriginatingIP, d.XOriginatingIP),   // string
		mailEncoder.String(fieldContentType, d.ContentType),         // string
		mailEncoder.String(fieldEnvelopeTo, d.EnvelopeTo),           // string
		// d.Body,            // []*MailPart
		mailEncoder.String(fieldClientIP, d.ClientIP), // string
		mailEncoder.String(fieldServerIP, d.ServerIP), // string
		mailEncoder.String(fieldID, d.ID),             // string
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *Mail) Analyze() {}

// NetcapType returns the type of the current audit record
func (d *Mail) NetcapType() Type {
	return Type_NC_Mail
}
