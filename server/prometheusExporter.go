package main

// // Metrics for prometheus
// type Metrics struct {
// 	UniqueFingerprints prometheus.Gauge
// 	Distribution       *prometheus.GaugeVec
// }

// // Register metrics
// func (m *Metrics) Register() error {
// 	if err := prometheus.Register(m.UniqueFingerprints); err != nil {
// 		return errors.Wrap(err, "unique fingerprints metric")
// 	}
// 	if err := prometheus.Register(m.Distribution); err != nil {
// 		return errors.Wrap(err, "distribution metric")
// 	}
// 	return nil
// }

// // Unregister metrics
// func (m *Metrics) Unregister() {
// 	prometheus.Unregister(m.UniqueFingerprints)
// 	prometheus.Unregister(m.Distribution)
// }

// func initPrometheus() {

// 	prometheus.MustRegister(detectorGauge)

// 	// Create error channels
// 	metricsErr := make(chan error, 1)

// 	// Start the metrics server.
// 	// Only start the metrics server in socket mode or the bind address would conflict with each new process.
// 	go func() {
// 		Log.Info("Starting prometheus metrics HTTP server on: ", defaultMetricsBindAddr)
// 		http.Handle("/metrics", promhttp.Handler())
// 		metricsErr <- http.ListenAndServe(defaultMetricsBindAddr, nil)
// 	}()

// 	select {
// 	case err := <-metricsErr:
// 		if err != nil {
// 			Log.WithError(err).Error("got a metrics error")
// 		}
// 	}
// }

// var detectorGauge = prometheus.NewGauge(prometheus.GaugeOpts{
// 	Name: "nad_detectors",
// 	Help: "Current number of active detectors.",
// })

// func createDetectorMetrics(group string) *DetectorMetrics {

// 	var (
// 		labels = prometheus.Labels{
// 			"task":  "task",
// 			"node":  "h.nodeID",
// 			"group": "group",
// 		}
// 		metrics = &DetectorMetrics{
// 			WindowCount: prometheus.NewCounter(
// 				prometheus.CounterOpts{
// 					Name:        "windows_total",
// 					Help:        "Number of windows processed",
// 					ConstLabels: labels,
// 				},
// 			),
// 			PointCount: prometheus.NewCounter(prometheus.CounterOpts{
// 				Name:        "points_total",
// 				Help:        "Number of points processed",
// 				ConstLabels: labels,
// 			}),
// 			AnomalousCount: prometheus.NewCounter(prometheus.CounterOpts{
// 				Name:        "anomalies_total",
// 				Help:        "Number of anomalies detected",
// 				ConstLabels: labels,
// 			}),
// 			FingerprinterMetrics: make([]*Metrics, len(fingerprinterInitializers)),
// 		}
// 		i = 0
// 	)

// 	for name := range fingerprinterInitializers {

// 		var (
// 			fLabels = prometheus.Labels{
// 				"task":          "h.taskID",
// 				"node":          "h.nodeID",
// 				"group":         "group",
// 				"fingerprinter": name,
// 			}
// 		)
// 		metrics.FingerprinterMetrics[i] = &Metrics{
// 			UniqueFingerprints: prometheus.NewGauge(prometheus.GaugeOpts{
// 				Name:        "unique_fingerprints",
// 				Help:        "Current number of unique fingerprints",
// 				ConstLabels: fLabels,
// 			}),
// 			Distribution: prometheus.NewGaugeVec(
// 				prometheus.GaugeOpts{
// 					Name:        "fingerprints_distribution",
// 					Help:        "Distribution of counts per unique fingerprint",
// 					ConstLabels: fLabels,
// 				},
// 				[]string{"fp"},
// 			),
// 		}
// 		// Unregistering a metric does not forget the last value.
// 		// We need to explicitly reset the value.
// 		metrics.FingerprinterMetrics[i].UniqueFingerprints.Set(0)
// 		i++
// 	}
// 	return metrics
// }
