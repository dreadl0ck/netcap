package capture

import "github.com/dreadl0ck/netcap/cmd/capture/webui"

// runtimeConfigFromFlags builds the analysis settings the WebUI passes to
// capture helpers. Local and service mode share it: service mode used to
// build its own copy that omitted capture evidence and flow exports, so
// try.netcap.io ran every analysis without a capture manifest.
func runtimeConfigFromFlags() *webui.RuntimeConfig {
	evidenceLinks := flagEvidenceLinks
	return &webui.RuntimeConfig{
		Features:      map[string]bool{"network-detection": flagNetworkDetection, "evidence-links": flagEvidenceLinks.Enabled, "dns-resolution-context": flagDNSResolutionContext},
		EvidenceLinks: &evidenceLinks,
		Compress:      flagCompress,
		Buffer:        flagBuffer,
		Workers:       flagWorkers,
		PacketBuffer:  flagPacketBuffer,
		MemBufSize:    flagMemBufferSize,
		Interface:     flagInterface,
		PromiscMode:   flagPromiscMode,
		SnapLen:       flagSnapLen,
		BaseLayer:     flagBaseLayer,
		DecodeOptions: flagDecodeOptions,
		Payload:       flagPayload,
		Context:       flagContext,
		MacDB:         flagMACDB,

		ServiceDB:             flagServiceDB,
		GeoDB:                 flagGeolocationDB,
		GeoProviders:          flagGeoProviders,
		ReverseDNS:            flagReverseDNS,
		LocalDNS:              flagLocalDNS,
		ReassembleConnections: flagReassembleConnections,
		FlowExports:           flagFlowExports,
		CaptureEvidence:       flagCaptureEvidence, RetainPackets: flagRetainPackets, PacketSegmentBytes: flagPacketSegmentBytes, PacketRetentionBytes: flagPacketRetentionBytes,
		FlowExportPorts:            flagFlowExportPorts,
		FlushEvery:                 flagFlushevery,
		Checksum:                   flagChecksum,
		NoOptCheck:                 flagNooptcheck,
		IgnoreFSMErr:               flagIgnorefsmerr,
		AllowMissingInit:           flagAllowmissinginit,
		ModbusRTUEndpoints:         flagModbusRTUEndpoints,
		DNP3PointMap:               flagDNP3PointMap,
		ClosePendingTimeout:        flagClosePendingTimeout,
		CloseInactiveTimeout:       flagCloseInactiveTimeout,
		LiveMaintenanceInterval:    flagLiveMaintenanceInterval,
		LiveFlushInterval:          flagLiveFlushInterval,
		MaxRetainedTCPBytes:        flagMaxRetainedTCPBytes,
		MaxRetainedReassemblyBytes: flagMaxRetainedReassemblyBytes,
		IncrementalHTTP:            flagIncrementalHTTP,
		MaxRetainedTCPStateBytes:   flagMaxRetainedTCPStateBytes,
		MaxAggregateStateBytes:     flagMaxAggregateStateBytes,
		LinkProfilesPath:           flagLinkProfiles,
		CaptureTimeIdleExpiry:      flagCaptureTimeIdleExpiry,
		Proto:                      flagProto,
		JSON:                       flagJSON,
		CSV:                        flagCSV,
		Elastic:                    flagElastic,
		ElasticAddrs:               flagElasticAddrs,
		ElasticUser:                flagElasticUser,
		IgnoreUnknown:              flagIgnoreUnknown,
		FreeOSMemory:               flagFreeOSMemory,
		ConnFlushInterval:          flagConnFlushInterval,
		ConnTimeout:                flagConnTimeOut,
		FlowFlushInterval:          flagFlowFlushInterval,
		FlowTimeout:                flagFlowTimeOut,
		Entropy:                    flagCalcEntropy,
		TCPDebug:                   flagTCPDebug,
		SaveConns:                  flagSaveConns,
		DefragIPv4:                 flagDefragIPv4,
		HexDump:                    flagHexdump,
		BannerSize:                 flagBannerSize,
	}
}
