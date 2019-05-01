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
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsBFD = []string{
	"Timestamp",
	"Version",
	"Diagnostic",
	"State",
	"Poll",
	"Final",
	"ControlPlaneIndependent",
	"AuthPresent",
	"Demand",
	"Multipoint",
	"DetectMultiplier",
	"MyDiscriminator",
	"YourDiscriminator",
	"DesiredMinTxInterval",
	"RequiredMinRxInterval",
	"RequiredMinEchoRxInterval",
	"AuthHeader",
}

func (a BFD) CSVHeader() []string {
	return filter(fieldsBFD)
}

func (a BFD) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),                        // int32
		formatInt32(a.Diagnostic),                     // int32
		formatInt32(a.State),                          // int32
		strconv.FormatBool(a.Poll),                    // bool
		strconv.FormatBool(a.Final),                   // bool
		strconv.FormatBool(a.ControlPlaneIndependent), // bool
		strconv.FormatBool(a.AuthPresent),             // bool
		strconv.FormatBool(a.Demand),                  // bool
		strconv.FormatBool(a.Multipoint),              // bool
		formatInt32(a.DetectMultiplier),               // int32
		formatInt32(a.MyDiscriminator),                // int32
		formatInt32(a.YourDiscriminator),              // int32
		formatInt32(a.DesiredMinTxInterval),           // int32
		formatInt32(a.RequiredMinRxInterval),          // int32
		formatInt32(a.RequiredMinEchoRxInterval),      // int32
		a.AuthHeader.GetString(),                      // *BFDAuthHeader
	})
}

func (a BFD) NetcapTimestamp() string {
	return a.Timestamp
}

func (a BFDAuthHeader) GetString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(int32(a.AuthType)))
	b.WriteString(Separator)
	b.WriteString(formatInt32(int32(a.KeyID)))
	b.WriteString(Separator)
	b.WriteString(formatInt32(int32(a.SequenceNumber)))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(a.Data))
	b.WriteString(End)
	return b.String()
}

func (a BFD) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var bfdMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_BFD.String()),
		Help: Type_NC_BFD.String() + " audit records",
	},
	fieldsBFD,
)

func init() {
	prometheus.MustRegister(bfdMetric)
}

func (a BFD) Inc() {
	bfdMetric.WithLabelValues(a.CSVRecord()...).Inc()
}
