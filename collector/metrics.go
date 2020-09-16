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

package collector

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	allProtosTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nc_protocols_total",
			Help: "Counter for all protocols encountered during parsing the network traffic",
		},
		[]string{"Protocol"},
	)
	unknownProtosTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nc_unknown_protocols_total",
			Help: "Counter for all unknown protocols encountered during parsing the network traffic",
		},
		[]string{"Protocol"},
	)
	decodingErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nc_decoding_errors_total",
			Help: "Counter for all decoding errors encountered during parsing the network traffic",
		},
		[]string{"Protocol", "Error"},
	)
	customDecoderTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_custom_decoder_time",
			Help: "Time taken for each custom decoder invocation",
		},
		[]string{"Decoder"},
	)
	gopacketDecoderTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_gopacket_decoder_time",
			Help: "Time taken for each gopacket decoder invocation",
		},
		[]string{"Decoder"},
	)
	reassemblyTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_reassembly_time",
			Help: "Time taken for each packet to be processed by the TCP reassembly",
		},
		[]string{},
	)
	newPacketsPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_new_packets_per_second",
			Help: "Number of new packets being processed per second",
		},
		[]string{},
	)
)

func init() {
	prometheus.MustRegister(
		allProtosTotal,
		unknownProtosTotal,
		decodingErrorsTotal,
		customDecoderTime,
		gopacketDecoderTime,
		reassemblyTime,
		newPacketsPerSecond,
	)
}
