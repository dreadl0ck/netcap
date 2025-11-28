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
