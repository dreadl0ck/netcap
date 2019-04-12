package metrics

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/mgutz/ansi"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// prefix for all prometheus metrics exposed by our proxy
const prefix = "netcap_"

// init is used to register the prometheus metrics on startup
func init() {

	// counters
	prometheus.MustRegister(
		upTime,
	)
}

var (
	// Start time
	startTime = time.Now()

	// Uptime
	upTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: prefix + "uptime",
			Help: "Number of seconds since the last restart",
		},
		[]string{},
	)
)

// ServeMetricsAt exposes the prometheus at the given address
func ServeMetricsAt(addr string) {

	var metricsHandler = promhttp.Handler()
	fmt.Println(ansi.Yellow+"serving metrics at:", addr+"/metrics"+ansi.Reset)

	go func() {
		// serve prometheus metrics on the /metrics route
		http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			upTime.WithLabelValues().Set(math.RoundToEven(time.Since(startTime).Seconds()))
			metricsHandler.ServeHTTP(w, r)
		})
		log.Fatal("failed to serve metrics: ", http.ListenAndServe(addr, nil))
	}()
}
