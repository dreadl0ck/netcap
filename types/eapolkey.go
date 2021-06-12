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
	fieldKeyDescriptorType    = "KeyDescriptorType"
	fieldKeyDescriptorVersion = "KeyDescriptorVersion"
	fieldKeyType              = "KeyType"
	fieldKeyIndex             = "KeyIndex"
	fieldInstall              = "Install"
	fieldKeyACK               = "KeyACK"
	fieldKeyMIC               = "KeyMIC"
	fieldSecure               = "Secure"
	fieldMICError             = "MICError"
	fieldRequest              = "Request"
	fieldHasEncryptedKeyData  = "HasEncryptedKeyData"
	fieldSMKMessage           = "SMKMessage"
	fieldKeyLength            = "KeyLength"
	fieldReplayCounter        = "ReplayCounter"
	fieldNonce                = "Nonce"
	fieldIV                   = "IV"
	fieldRSC                  = "RSC"
	fieldMIC                  = "MIC"
	fieldKeyDataLength        = "KeyDataLength"
	fieldEncryptedKeyData     = "EncryptedKeyData"
)

var fieldsEAPOLKey = []string{
	fieldTimestamp,
	fieldKeyDescriptorType,    // int32
	fieldKeyDescriptorVersion, // int32
	fieldKeyType,              // int32
	fieldKeyIndex,             // int32
	fieldInstall,              // bool
	fieldKeyACK,               // bool
	fieldKeyMIC,               // bool
	fieldSecure,               // bool
	fieldMICError,             // bool
	fieldRequest,              // bool
	fieldHasEncryptedKeyData,  // bool
	fieldSMKMessage,           // bool
	fieldKeyLength,            // int32
	fieldReplayCounter,        // uint64
	//fieldNonce,                // []byte
	//fieldIV,                   // []byte
	fieldRSC, // uint64
	fieldID,  // uint64
	//fieldMIC,                  // []byte
	fieldKeyDataLength, // int32
	//fieldEncryptedKeyData,     // []byte
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
		//hex.EncodeToString(a.Nonce),               // []byte
		//hex.EncodeToString(a.IV),                  // []byte
		formatUint64(a.RSC), // uint64
		formatUint64(a.ID),  // uint64
		//hex.EncodeToString(a.MIC),                 // []byte
		formatInt32(a.KeyDataLength), // int32
		//hex.EncodeToString(a.EncryptedKeyData),    // []byte
	})
}

// Time returns the timestamp associated with the audit record.
func (a *EAPOLKey) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *EAPOLKey) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

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

var eapolkeyEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *EAPOLKey) Encode() []string {
	return filter([]string{
		eapolkeyEncoder.Int64(fieldTimestamp, a.Timestamp),
		eapolkeyEncoder.Int32(fieldKeyDescriptorType, a.KeyDescriptorType),       // int32
		eapolkeyEncoder.Int32(fieldKeyDescriptorVersion, a.KeyDescriptorVersion), // int32
		eapolkeyEncoder.Int32(fieldKeyType, a.KeyType),                           // int32
		eapolkeyEncoder.Int32(fieldKeyIndex, a.KeyIndex),                         // int32
		eapolkeyEncoder.Bool(a.Install),                                          // bool
		eapolkeyEncoder.Bool(a.KeyACK),                                           // bool
		eapolkeyEncoder.Bool(a.KeyMIC),                                           // bool
		eapolkeyEncoder.Bool(a.Secure),                                           // bool
		eapolkeyEncoder.Bool(a.MICError),                                         // bool
		eapolkeyEncoder.Bool(a.Request),                                          // bool
		eapolkeyEncoder.Bool(a.HasEncryptedKeyData),                              // bool
		eapolkeyEncoder.Bool(a.SMKMessage),                                       // bool
		eapolkeyEncoder.Int32(fieldKeyLength, a.KeyLength),                       // int32
		eapolkeyEncoder.Uint64(fieldReplayCounter, a.ReplayCounter),              // uint64
		//hex.EncodeToString(a.Nonce),               // []byte
		//hex.EncodeToString(a.IV),                  // []byte
		eapolkeyEncoder.Uint64(fieldRSC, a.RSC), // uint64
		eapolkeyEncoder.Uint64(fieldID, a.ID),   // uint64
		//hex.EncodeToString(a.MIC),                 // []byte
		eapolkeyEncoder.Int32(fieldKeyDataLength, a.KeyDataLength), // int32
		//hex.EncodeToString(a.EncryptedKeyData),    // []byte
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *EAPOLKey) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *EAPOLKey) NetcapType() Type {
	return Type_NC_EAPOLKey
}
