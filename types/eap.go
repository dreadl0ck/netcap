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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsEAP = []string{
	"Timestamp",
	"Code",     // int32
	"Id",       // int32
	"Length",   // int32
	"Type",     // int32
	"TypeData", // []byte
}

func (a *EAP) CSVHeader() []string {
	return filter(fieldsEAP)
}

func (a *EAP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Code),            // int32
		formatInt32(a.Id),              // int32
		formatInt32(a.Length),          // int32
		formatInt32(a.Type),            // int32
		hex.EncodeToString(a.TypeData), // []byte
	})
}

func (a *EAP) Time() string {
	return a.Timestamp
}

func (a *EAP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var eapMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EAP.String()),
		Help: Type_NC_EAP.String() + " audit records",
	},
	fieldsEAP[1:],
)

func init() {
	prometheus.MustRegister(eapMetric)
}

func (a *EAP) Inc() {
	eapMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *EAP) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr
func (a *EAP) Src() string {
	return ""
}

func (a *EAP) Dst() string {
	return ""
}
