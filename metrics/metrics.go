package metrics

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsRoute = "/metrics"

var (
	// Start time
	startTime = time.Now()

	// Uptime
	upTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_uptime",
			Help: "Number of seconds since the last restart",
		},
		[]string{},
	)
)

// ServeMetricsAt exposes the prometheus at the given address
func ServeMetricsAt(addr string) {

	fmt.Println("starting to serve metrics at:", addr+metricsRoute)

	go func() {
		metricsHandler := promhttp.Handler()

		// serve prometheus metrics on the /metrics route
		http.HandleFunc(metricsRoute, func(w http.ResponseWriter, r *http.Request) {
			upTime.WithLabelValues().Set(math.RoundToEven(time.Since(startTime).Seconds()))
			metricsHandler.ServeHTTP(w, r)
		})
		log.Fatal("failed to serve metrics: ", http.ListenAndServe(addr, nil))
	}()
}
