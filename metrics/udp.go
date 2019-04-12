package metrics

import "github.com/prometheus/client_golang/prometheus"

var UDP = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: prefix + "udp",
		Help: "UDP audit records",
	},
	[]string{
		"SrcPort",
		"DstPort",
		"Length",
		"Checksum",
		"PayloadEntropy",
		"PayloadSize",
		"Payload",
	},
)
