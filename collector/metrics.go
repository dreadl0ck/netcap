/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
