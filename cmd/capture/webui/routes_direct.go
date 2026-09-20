//go:build !appstore

package webui

import "net/http"

func registerEditionRoutes(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("/api/dbs", s.handleDatabaseInfo)
	mux.HandleFunc("/api/dbs/update", s.handleUpdateDatabases)
	mux.HandleFunc("/api/dpi", s.handleDPIInfo)
	mux.HandleFunc("/api/dpi/preferences", s.handleDPIPreferences)
	mux.HandleFunc("/api/yara/status", s.handleYaraStatus)
	mux.HandleFunc("/api/yara/rules", s.handleYaraRules)
	mux.HandleFunc("/api/yara/rules/upload", s.handleUploadYaraRule)
	mux.HandleFunc("/api/yara/rules/", s.handleYaraRuleRouter)
	mux.HandleFunc("/api/yara/scan", s.handleYaraScan)
	mux.HandleFunc("/api/yara/scan-file", s.handleYaraScanFile)
	mux.HandleFunc("/api/service-probes", s.handleServiceProbes)
	mux.HandleFunc("/api/service-probes/", s.handleServiceProbeRouter)
	mux.HandleFunc("/api/service-probes/test", s.handleTestServiceProbe)
	mux.HandleFunc("/api/service-probes/export", s.handleExportServiceProbes)
	mux.HandleFunc("/api/service-probes/import", s.handleImportServiceProbes)
	mux.HandleFunc("/api/injection-rules", s.handleInjectionRules)
	mux.HandleFunc("/api/injection-rules/", s.handleInjectionRule)
	mux.HandleFunc("/api/injection-events", s.handleInjectionEvents)
	mux.HandleFunc("/api/injection-events/clear", s.handleInjectionEventsManage)
	mux.HandleFunc("/api/injection-stats", s.handleInjectionStats)
	mux.HandleFunc("/api/injection-actions", s.handleInjectionActions)
	mux.HandleFunc("/api/network-interfaces", s.handleNetworkInterfaces)
	mux.HandleFunc("/api/stop-capture", s.handleStopCapture)
}
