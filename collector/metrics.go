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
)

func init() {
	prometheus.MustRegister(allProtosTotal)
	prometheus.MustRegister(unknownProtosTotal)
	prometheus.MustRegister(decodingErrorsTotal)
}
