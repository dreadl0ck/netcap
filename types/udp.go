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

var fieldsUDP = []string{
	"Timestamp",
	"SrcPort",
	"DstPort",
	"Length", // redundant: PayloadSize + UDP Header Size = Length, remove field from audit record
	"Checksum",
	"PayloadEntropy",
	"PayloadSize",
	"Payload",
	"SrcIP",
	"DstIP",
}

func (u UDP) CSVHeader() []string {
	return filter(fieldsUDP)
}

func (u UDP) CSVRecord() []string {
	// prevent accessing nil pointer
	if u.Context == nil {
		u.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(u.Timestamp),                      // string
		formatInt32(u.SrcPort),                            // int32
		formatInt32(u.DstPort),                            // int32
		formatInt32(u.Length),                             // int32
		formatInt32(u.Checksum),                           // int32
		strconv.FormatFloat(u.PayloadEntropy, 'f', 8, 64), // float64
		formatInt32(u.PayloadSize),                        // int32
		hex.EncodeToString(u.Payload),
		u.Context.SrcIP,
		u.Context.DstIP,
	})
}

func (u UDP) Time() string {
	return u.Timestamp
}

func (u UDP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}

var (
	udpMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_UDP.String()),
			Help: Type_NC_UDP.String() + " audit records",
		},
		fieldsUDPMetrics,
	)
	udpPayloadEntropy = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_UDP.String()) + "_entropy",
			Help:    Type_NC_UDP.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// fieldsUDPMetrics,
		[]string{},
	)
	udpPayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_UDP.String()) + "_size",
			Help:    Type_NC_UDP.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// fieldsUDPMetrics,
		[]string{},
	)
)

var fieldsUDPMetrics = []string{
	"SrcPort",
	"DstPort",
}

func (u UDP) metricValues() []string {
	return []string{
		formatInt32(u.SrcPort), // int32
		formatInt32(u.DstPort), // int32
	}
}

func init() {
	prometheus.MustRegister(udpMetric)
	prometheus.MustRegister(udpPayloadEntropy)
	prometheus.MustRegister(udpPayloadSize)
}

func (u UDP) Inc() {
	udpMetric.WithLabelValues(u.metricValues()...).Inc()
	udpPayloadEntropy.WithLabelValues().Observe(u.PayloadEntropy)
	udpPayloadSize.WithLabelValues().Observe(float64(u.PayloadSize))
}

func (a *UDP) SetPacketContext(ctx *PacketContext) {

	// create new context and only add information that is
	// not yet present on the audit record type
	a.Context = &PacketContext{
		SrcIP: ctx.SrcIP,
		DstIP: ctx.DstIP,
	}
}

func (a UDP) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a UDP) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
