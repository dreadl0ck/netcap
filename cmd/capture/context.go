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

package capture

import (
	"time"

	"github.com/urfave/cli/v3"
)

// Global flag variables for helper functions
var (
	flagGenerateConfig                 bool
	flagGenerateElasticIndices         bool
	flagInput                          string
	flagMetricsAddr                    string
	flagOutDir                         string
	flagTimeout                        time.Duration
	flagLabels                         string
	flagScatterDuration                time.Duration
	flagScatter                        bool
	flagPPS                            bool
	flagBPF                            string
	flagInclude                        string
	flagExclude                        string
	flagDecoders                       bool
	flagPrintProtocolOverview          bool
	flagInterface                      string
	flagCompress                       bool
	flagBuffer                         bool
	flagWorkers                        int
	flagPacketBuffer                   int
	flagAnalyzer                       string
	flagCPUProfile                     bool
	flagMemProfile                     bool
	flagIgnoreUnknown                  bool
	flagPromiscMode                    bool
	flagSnapLen                        int
	flagTime                           bool
	flagBaseLayer                      string
	flagDecodeOptions                  string
	flagPayload                        bool
	flagCSV                            bool
	flagUNIX                           bool
	flagNull                           bool
	flagElastic                        bool
	flagElasticAddrs                   string
	flagElasticUser                    string
	flagElasticPass                    string
	flagBulkSizeGoPacket               int
	flagBulkSizeCustom                 int
	flagKibanaEndpoint                 string
	flagProto                          bool
	flagJSON                           bool
	flagContext                        bool
	flagHTTPShutdown                   bool
	flagMemBufferSize                  int
	flagListInterfaces                 bool
	flagQuiet                          bool
	flagPrintProgress                  bool
	flagFileStorage                    string
	flagFileConfig                     string
	flagReverseDNS                     bool
	flagLocalDNS                       bool
	flagMACDB                          bool
	flagJA4DB                          bool
	flagServiceDB                      bool
	flagGeolocationDB                  bool
	flagDPI                            bool
	flagDPIModules                     string
	flagFreeOSMemory                   int
	flagReassembleConnections          bool
	flagTCPDebug                       bool
	flagSaveConns                      bool
	flagCalcEntropy                    bool
	flagLogErrors                      bool
	flagFlushevery                     int
	flagDefragIPv4                     bool
	flagChecksum                       bool
	flagNooptcheck                     bool
	flagIgnorefsmerr                   bool
	flagAllowmissinginit               bool
	flagModbusRTUEndpoints             string
	flagHexdump                        bool
	flagWaitForConnections             bool
	flagWriteincomplete                bool
	flagStreamDecoderBufSize           int
	flagReassemblyDebug                bool
	flagYes                            bool
	flagDebug                          bool
	flagMemprofile                     string
	flagPprof                          string
	flagConnFlushInterval              int
	flagConnTimeOut                    time.Duration
	flagFlowFlushInterval              int
	flagFlowTimeOut                    time.Duration
	flagClosePendingTimeout            time.Duration
	flagCloseInactiveTimeout           time.Duration
	flagUseRE2                         bool
	flagStopAfterHarvesterMatch        bool
	flagStopAfterServiceProbeMatch     bool
	flagStopAfterServiceCategoryMiss   bool
	flagIgnoreInitErrs                 bool
	flagDisableGenericVersionHarvester bool
	flagRemoveClosedStreams            bool
	flagEncode                         bool
	flagBannerSize                     int
	flagHarvesterBannerSize            int
	flagCustomCredsRegex               string
	flagHarvestersConfig               string
	flagStreamBufferSize               int
	flagNumStreamWorkers               int
	flagMaxStreamBytes                 int
	flagMaxBufferedPagesPerConnection  int
	flagMaxBufferedPagesTotal          int
	flagCompressionBlockSize           int
	flagCompressionLevel               string
	flagHTTP                           string
	flagHTTPAssets                     string
	flagService                        bool
	flagServiceDataDir                 string
	flagServiceMaxFileSize             int64
	flagServiceMaxPerHour              int
	flagServiceExpiry                  int
	flagServiceCleanup                 int
	flagServiceMaxStorage              int64
	flagServicePreloadLargestN         int
	flagServiceEnforceMaxSizePreload   bool
	flagFilter                         string
	flagRules                          string
	flagApprovedWorkstations           string
	flagDev                            bool
	flagProtoSearchPaths               []string
	flagProtoShowAlternatives          bool
	flagProtoMessageTypes              []string
)

// setFlagsFromContext populates global flag variables from CLI context
func setFlagsFromContext(c *cli.Command) {
	flagGenerateConfig = c.Bool("gen-config")
	flagGenerateElasticIndices = c.Bool("gen-elastic-indices")
	flagInput = c.String("read")
	flagMetricsAddr = c.String("metrics")
	flagOutDir = c.String("out")
	flagTimeout = c.Duration("timeout")
	flagLabels = c.String("labels")
	flagScatterDuration = c.Duration("scatter-duration")
	flagScatter = c.Bool("scatter")
	flagPPS = c.Bool("pps")
	flagBPF = c.String("bpf")
	flagInclude = c.String("include")
	flagExclude = c.String("exclude")
	flagDecoders = c.Bool("decoders")
	flagPrintProtocolOverview = c.Bool("overview")
	flagInterface = c.String("iface")
	flagCompress = c.Bool("compress")
	flagBuffer = c.Bool("buf")
	flagWorkers = c.Int("workers")
	flagPacketBuffer = c.Int("pbuf")
	flagAnalyzer = c.String("analyzer")
	flagCPUProfile = c.Bool("cpuprof")
	flagMemProfile = c.Bool("memprof")
	flagIgnoreUnknown = c.Bool("ignore-unknown")
	flagPromiscMode = c.Bool("promisc")
	flagSnapLen = c.Int("snaplen")
	flagTime = c.Bool("time")
	flagBaseLayer = c.String("base")
	flagDecodeOptions = c.String("opts")
	flagPayload = c.Bool("payload")
	flagCSV = c.Bool("csv")
	flagUNIX = c.Bool("unix")
	flagNull = c.Bool("null")
	flagElastic = c.Bool("elastic")
	flagElasticAddrs = c.String("elastic-addrs")
	flagElasticUser = c.String("elastic-user")
	flagElasticPass = c.String("elastic-pass")
	flagBulkSizeGoPacket = c.Int("elastic-bulk-gopacket")
	flagBulkSizeCustom = c.Int("elastic-bulk-custom")
	flagKibanaEndpoint = c.String("kibana")
	flagProto = c.Bool("proto")
	flagJSON = c.Bool("json")
	flagContext = c.Bool("context")
	flagHTTPShutdown = c.Bool("http-shutdown")
	flagMemBufferSize = c.Int("membuf-size")
	flagListInterfaces = c.Bool("interfaces")
	flagQuiet = c.Bool("quiet")
	flagPrintProgress = c.Bool("progress")
	flagFileStorage = c.String("fileStorage")
	flagFileConfig = c.String("file-config")
	flagReverseDNS = c.Bool("reverse-dns")
	flagLocalDNS = c.Bool("local-dns")
	flagMACDB = c.Bool("macDB")
	flagJA4DB = c.Bool("ja4DB")
	flagServiceDB = c.Bool("serviceDB")
	flagGeolocationDB = c.Bool("geoDB")
	flagDPI = c.Bool("dpi")
	flagDPIModules = c.String("dpi-modules")
	flagFreeOSMemory = c.Int("free-os-mem")
	flagReassembleConnections = c.Bool("reassemble-connections")
	flagTCPDebug = c.Bool("tcp-debug")
	flagSaveConns = c.Bool("conns")
	flagCalcEntropy = c.Bool("entropy")
	flagLogErrors = c.Bool("log-errors")
	flagFlushevery = c.Int("flushevery")
	flagDefragIPv4 = c.Bool("ip4defrag")
	flagChecksum = c.Bool("checksum")
	flagNooptcheck = c.Bool("nooptcheck")
	flagIgnorefsmerr = c.Bool("ignorefsmerr")
	flagAllowmissinginit = c.Bool("allowmissinginit")
	flagModbusRTUEndpoints = c.String("modbus-rtu-endpoints")
	flagHexdump = c.Bool("hexdump")
	flagWaitForConnections = c.Bool("wait-conns")
	flagWriteincomplete = c.Bool("writeincomplete")
	flagStreamDecoderBufSize = c.Int("sbuf-size")
	flagReassemblyDebug = c.Bool("reassembly-debug")
	flagYes = c.Bool("y")
	flagDebug = c.Bool("debug")
	flagMemprofile = c.String("memprofile")
	flagPprof = c.String("pprof")
	flagConnFlushInterval = c.Int("conn-flush-interval")
	flagConnTimeOut = c.Duration("conn-timeout")
	flagFlowFlushInterval = c.Int("flow-flush-interval")
	flagFlowTimeOut = c.Duration("flow-timeout")
	flagClosePendingTimeout = c.Duration("close-pending-timeout")
	flagCloseInactiveTimeout = c.Duration("close-inactive-timeout")
	flagUseRE2 = c.Bool("re2")
	flagStopAfterHarvesterMatch = c.Bool("stop-after-harvester-match")
	flagStopAfterServiceProbeMatch = c.Bool("stop-after-service-match")
	flagStopAfterServiceCategoryMiss = c.Bool("stop-after-service-category-miss")
	flagIgnoreInitErrs = c.Bool("ignore-init-errors")
	flagDisableGenericVersionHarvester = c.Bool("disable-generic-software-harvester")
	flagRemoveClosedStreams = c.Bool("remove-closed-streams")
	flagEncode = c.Bool("encode")
	flagBannerSize = c.Int("bsize")
	flagHarvesterBannerSize = c.Int("hbsize")
	flagCustomCredsRegex = c.String("reCustom")
	flagHarvestersConfig = c.String("harvesters-config")
	flagStreamBufferSize = c.Int("stream-buffer")
	flagNumStreamWorkers = c.Int("stream-workers")
	flagMaxStreamBytes = c.Int("max-stream-bytes")
	flagMaxBufferedPagesPerConnection = c.Int("max-buffered-pages-per-conn")
	flagMaxBufferedPagesTotal = c.Int("max-buffered-pages-total")
	flagCompressionBlockSize = c.Int("compression-block-size")
	flagCompressionLevel = c.String("compression-level")
	flagHTTP = c.String("http")
	flagHTTPAssets = c.String("http-assets")
	flagService = c.Bool("service")
	flagServiceDataDir = c.String("service-data-dir")
	flagServiceMaxFileSize = c.Int64("service-max-file-size")
	flagServiceMaxPerHour = c.Int("service-max-per-hour")
	flagServiceExpiry = c.Int("service-expiry")
	flagServiceCleanup = c.Int("service-cleanup")
	flagServiceMaxStorage = c.Int64("service-max-storage")
	flagServicePreloadLargestN = c.Int("service-preload-largest-n")
	flagServiceEnforceMaxSizePreload = c.Bool("service-enforce-max-size-preload")
	flagFilter = c.String("filter")
	flagRules = c.String("rules")
	flagApprovedWorkstations = c.String("approved-workstations")
	flagDev = c.Bool("dev")
	flagProtoSearchPaths = c.StringSlice("proto-paths")
	flagProtoShowAlternatives = c.Bool("proto-show-alternatives")
	flagProtoMessageTypes = c.StringSlice("proto-message-types")
}
