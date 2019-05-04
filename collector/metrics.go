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
