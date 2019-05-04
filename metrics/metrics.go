package metrics

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/dreadl0ck/netcap/collector"
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
	// NumPackets
	numPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nc_numpackets",
			Help: "Number of packets since the last restart",
		},
		[]string{},
	)
)

func init() {
	prometheus.MustRegister(upTime)
	prometheus.MustRegister(numPackets)
}

// ServeMetricsAt exposes the prometheus at the given address
func ServeMetricsAt(addr string, c *collector.Collector) {

	fmt.Println("starting to serve metrics at:", addr+metricsRoute)

	go func() {
		metricsHandler := promhttp.Handler()

		// serve prometheus metrics on the /metrics route
		http.HandleFunc(metricsRoute, func(w http.ResponseWriter, r *http.Request) {

			upTime.WithLabelValues().Set(math.RoundToEven(time.Since(startTime).Seconds()))

			if c != nil {
				numPackets.WithLabelValues().Set(float64(c.GetNumPackets()))
			}

			metricsHandler.ServeHTTP(w, r)
		})
		log.Fatal("failed to serve metrics: ", http.ListenAndServe(addr, nil))
	}()
}
