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

var fieldsARP = []string{
	"Timestamp",
	"AddrType",        // int32
	"Protocol",        // int32
	"HwAddressSize",   // int32
	"ProtAddressSize", // int32
	"Operation",       // int32
	"SrcHwAddress",    // []byte
	"SrcProtAddress",  // []byte
	"DstHwAddress",    // []byte
	"DstProtAddress",  // []byte
}

func (a *ARP) CSVHeader() []string {
	return filter(fieldsARP)
}

func (a *ARP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.AddrType),              // int32
		formatInt32(a.Protocol),              // int32
		formatInt32(a.HwAddressSize),         // int32
		formatInt32(a.ProtAddressSize),       // int32
		formatInt32(a.Operation),             // int32
		hex.EncodeToString(a.SrcHwAddress),   // []byte
		hex.EncodeToString(a.SrcProtAddress), // []byte
		hex.EncodeToString(a.DstHwAddress),   // []byte
		hex.EncodeToString(a.DstProtAddress), // []byte
	})
}

func (a *ARP) Time() string {
	return a.Timestamp
}

func (a *ARP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var arpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ARP.String()),
		Help: Type_NC_ARP.String() + " audit records",
	},
	fieldsARP[1:],
)

func init() {
	prometheus.MustRegister(arpMetric)
}

func (a *ARP) Inc() {
	arpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *ARP) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for ARP and return them here.
func (a *ARP) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for ARP and return them here
func (a *ARP) Dst() string {
	return ""
}
