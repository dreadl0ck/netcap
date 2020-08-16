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
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/utils"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsEAPOLKey = []string{
	"Timestamp",
	"KeyDescriptorType",    // int32
	"KeyDescriptorVersion", // int32
	"KeyType",              // int32
	"KeyIndex",             // int32
	"Install",              // bool
	"KeyACK",               // bool
	"KeyMIC",               // bool
	"Secure",               // bool
	"MICError",             // bool
	"Request",              // bool
	"HasEncryptedKeyData",  // bool
	"SMKMessage",           // bool
	"KeyLength",            // int32
	"ReplayCounter",        // uint64
	"Nonce",                // []byte
	"IV",                   // []byte
	"RSC",                  // uint64
	"ID",                   // uint64
	"MIC",                  // []byte
	"KeyDataLength",        // int32
	"EncryptedKeyData",     // []byte
}

// CSVHeader returns the CSV header for the audit record.
func (a *EAPOLKey) CSVHeader() []string {
	return filter(fieldsEAPOLKey)
}

// CSVRecord returns the CSV record for the audit record.
func (a *EAPOLKey) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.KeyDescriptorType),          // int32
		formatInt32(a.KeyDescriptorVersion),       // int32
		formatInt32(a.KeyType),                    // int32
		formatInt32(a.KeyIndex),                   // int32
		strconv.FormatBool(a.Install),             // bool
		strconv.FormatBool(a.KeyACK),              // bool
		strconv.FormatBool(a.KeyMIC),              // bool
		strconv.FormatBool(a.Secure),              // bool
		strconv.FormatBool(a.MICError),            // bool
		strconv.FormatBool(a.Request),             // bool
		strconv.FormatBool(a.HasEncryptedKeyData), // bool
		strconv.FormatBool(a.SMKMessage),          // bool
		formatInt32(a.KeyLength),                  // int32
		formatUint64(a.ReplayCounter),             // uint64
		hex.EncodeToString(a.Nonce),               // []byte
		hex.EncodeToString(a.IV),                  // []byte
		formatUint64(a.RSC),                       // uint64
		formatUint64(a.ID),                        // uint64
		hex.EncodeToString(a.MIC),                 // []byte
		formatInt32(a.KeyDataLength),              // int32
		hex.EncodeToString(a.EncryptedKeyData),    // []byte
	})
}

// Time returns the timestamp associated with the audit record.
func (a *EAPOLKey) Time() string {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *EAPOLKey) JSON() (string, error) {
	a.Timestamp = utils.TimeToUnixMilli(a.Timestamp)
	return jsonMarshaler.MarshalToString(a)
}

var eapPolKeyMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EAPOLKey.String()),
		Help: Type_NC_EAPOLKey.String() + " audit records",
	},
	fieldsEAPOLKey[1:],
)

// Inc increments the metrics for the audit record.
func (a *EAPOLKey) Inc() {
	eapPolKeyMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *EAPOLKey) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (a *EAPOLKey) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *EAPOLKey) Dst() string {
	return ""
}
