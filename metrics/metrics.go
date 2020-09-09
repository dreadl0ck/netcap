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

// Package metrics provides primitives for instrumentation via prometheus
package metrics

import (

	//  TODO: protect via auth?
	_ "expvar"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dreadl0ck/netcap/collector"
)

const metricsRoute = "/metrics"

var (
	// Start time.
	startTime = time.Now()

	// Uptime.
	upTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_uptime",
			Help: "Number of seconds since the last restart",
		},
		[]string{},
	)
	// NumPackets.
	numPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_numpackets",
			Help: "Number of packets since the last restart",
		},
		[]string{},
	)
)

// ServeMetricsAt exposes the prometheus at the given address.
func ServeMetricsAt(addr string, c *collector.Collector) {
	prometheus.MustRegister(upTime)
	prometheus.MustRegister(numPackets)

	fmt.Println("starting to serve metrics at:", addr+metricsRoute)

	go func() {
		metricsHandler := promhttp.Handler()

		// serve prometheus metrics on the /metrics route
		http.HandleFunc(metricsRoute, func(w http.ResponseWriter, r *http.Request) {
			upTime.WithLabelValues().Set(math.RoundToEven(time.Since(startTime).Seconds()))

			// kindly ask the collector for some stats
			if c != nil {
				numPackets.WithLabelValues().Set(float64(c.GetNumPackets()))
			}

			metricsHandler.ServeHTTP(w, r)
		})
		log.Fatal("failed to serve metrics: ", http.ListenAndServe(addr, nil))
	}()
}
