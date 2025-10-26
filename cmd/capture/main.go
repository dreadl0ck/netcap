/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package capture

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/dreadl0ck/netcap/analyze"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/decoder/stream/alert"
	"github.com/dreadl0ck/netcap/env"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"

	"github.com/dustin/go-humanize"
	"github.com/evilsocket/islazy/tui"
	"github.com/felixge/fgprof"
	"github.com/mgutz/ansi"

	_ "net/http/pprof"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/cmd/capture/webui"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/decoder/stream/exploit"
	httpstream "github.com/dreadl0ck/netcap/decoder/stream/http"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/decoder/stream/vulnerability"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/metrics"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// fileError tracks errors that occurred during file processing
type fileError struct {
	filename string
	err      error
}

// fileSummary contains summary statistics for a processed file
type fileSummary struct {
	filename         string
	auditRecordCount int64
	inputFileSize    int64
	outputTotalSize  int64
	processingTime   time.Duration
	err              error
}

// expandPcapFiles expands wildcards to find all pcap and pcapng files
func expandPcapFiles(pattern string) ([]string, error) {
	// Check if pattern contains wildcards
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") && !strings.Contains(pattern, "[") {
		// No wildcard, but still need to check if it's a directory or valid file
		info, err := os.Stat(pattern)
		if err != nil {
			return nil, err
		}

		if info.IsDir() {
			// It's a directory, silently skip it
			return []string{}, nil
		}

		// Check if it's a valid pcap/pcapng file
		if !strings.HasSuffix(strings.ToLower(pattern), ".pcap") && !strings.HasSuffix(strings.ToLower(pattern), ".pcapng") {
			// Not a pcap file, silently skip it
			return []string{}, nil
		}

		return []string{pattern}, nil
	}

	// Use filepath.Glob to expand the pattern
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	// Filter to only include .pcap and .pcapng files (not directories)
	var pcapFiles []string
	for _, match := range matches {
		// Check if it's a regular file (not a directory)
		info, err := os.Stat(match)
		if err != nil {
			// Skip files that can't be accessed
			continue
		}

		if info.IsDir() {
			// Skip directories
			continue
		}

		// Only include files with .pcap or .pcapng extension
		if strings.HasSuffix(strings.ToLower(match), ".pcap") || strings.HasSuffix(strings.ToLower(match), ".pcapng") {
			pcapFiles = append(pcapFiles, match)
		}
	}

	if len(pcapFiles) == 0 {
		return nil, fmt.Errorf("no pcap or pcapng files found matching pattern: %s", pattern)
	}

	return pcapFiles, nil
}

// getOutputDirForFile creates a unique output directory name for a given input file
func getOutputDirForFile(inputFile, baseOutDir string) string {
	// Get the base name without extension
	baseName := filepath.Base(inputFile)
	// Remove .pcap or .pcapng extension
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))

	// If no base output directory specified, use current directory
	if baseOutDir == "" {
		return baseName
	}

	// Create subdirectory within base output directory
	return filepath.Join(baseOutDir, baseName)
}

// uniqueFiles removes duplicate file paths from a slice
func uniqueFiles(files []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, file := range files {
		if !seen[file] {
			seen[file] = true
			result = append(result, file)
		}
	}

	return result
}

// writeSummaryTable writes a detailed summary table for multi-file processing
// to both stdout and a log file on disk using the tui.Table package
func writeSummaryTable(inputFiles []string, summaries []fileSummary, fileErrors []fileError, outDir string) {
	// Print header
	fmt.Println("\n================================================================================")
	fmt.Println("                         Multi-File Processing Summary                          ")
	fmt.Println("================================================================================")
	fmt.Printf("Total files processed: %d\n", len(inputFiles))
	fmt.Printf("Successful: %d\n", len(inputFiles)-len(fileErrors))
	fmt.Printf("Failed: %d\n", len(fileErrors))
	fmt.Printf("Timestamp: %s\n", time.Now().Format(time.RFC3339))
	fmt.Println("================================================================================")

	// Build table rows
	var rows [][]string
	var totalAuditRecords int64
	var totalInputSize int64
	var totalOutputSize int64
	var totalProcessingTime time.Duration

	for _, summary := range summaries {
		fileName := filepath.Base(summary.filename)
		if len(fileName) > 45 {
			fileName = fileName[:42] + "..."
		}

		status := ansi.Green + "OK" + ansi.Reset
		if summary.err != nil {
			status = ansi.Red + "ERROR" + ansi.Reset
		}

		rows = append(rows, []string{
			fileName,
			humanize.Comma(summary.auditRecordCount),
			humanize.Bytes(uint64(summary.inputFileSize)),
			humanize.Bytes(uint64(summary.outputTotalSize)),
			summary.processingTime.Round(time.Millisecond).String(),
			status,
		})

		totalAuditRecords += summary.auditRecordCount
		totalInputSize += summary.inputFileSize
		totalOutputSize += summary.outputTotalSize
		totalProcessingTime += summary.processingTime
	}

	// Add totals row
	rows = append(rows, []string{
		ansi.White + "TOTAL" + ansi.Reset,
		ansi.White + humanize.Comma(totalAuditRecords) + ansi.Reset,
		ansi.White + humanize.Bytes(uint64(totalInputSize)) + ansi.Reset,
		ansi.White + humanize.Bytes(uint64(totalOutputSize)) + ansi.Reset,
		ansi.White + totalProcessingTime.Round(time.Millisecond).String() + ansi.Reset,
		"",
	})

	// Print table to stdout (with colors)
	headers := []string{"Input File", "Audit Records", "Input Size", "Output Size", "Processing Time", "Status"}
	tui.Table(os.Stdout, headers, rows)
	fmt.Println()

	// Print error details if any
	if len(fileErrors) > 0 {
		fmt.Printf("%sErrors Encountered:%s\n", ansi.Red, ansi.Reset)
		fmt.Println("================================================================================")
		for i, fe := range fileErrors {
			fmt.Printf("%d. %s%s%s\n", i+1, ansi.Yellow, filepath.Base(fe.filename), ansi.Reset)
			fmt.Printf("   Error: %v\n\n", fe.err)
		}
	} else {
		fmt.Printf("%sAll files processed successfully!%s\n", ansi.Green, ansi.Reset)
	}

	// Write to log file (without ANSI color codes)
	summaryLogPath := filepath.Join(outDir, "multi-file-summary.log")
	summaryFile, err := os.Create(summaryLogPath)
	if err != nil {
		fmt.Printf("Warning: failed to create summary log file: %v\n", err)
		return
	}
	defer summaryFile.Close()

	// Write header to log file
	fmt.Fprintf(summaryFile, "================================================================================\n")
	fmt.Fprintf(summaryFile, "                         Multi-File Processing Summary                          \n")
	fmt.Fprintf(summaryFile, "================================================================================\n")
	fmt.Fprintf(summaryFile, "Total files processed: %d\n", len(inputFiles))
	fmt.Fprintf(summaryFile, "Successful: %d\n", len(inputFiles)-len(fileErrors))
	fmt.Fprintf(summaryFile, "Failed: %d\n", len(fileErrors))
	fmt.Fprintf(summaryFile, "Timestamp: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(summaryFile, "================================================================================\n\n")

	// Build rows without color codes for log file
	var plainRows [][]string
	for _, summary := range summaries {
		fileName := filepath.Base(summary.filename)
		if len(fileName) > 45 {
			fileName = fileName[:42] + "..."
		}

		status := "OK"
		if summary.err != nil {
			status = "ERROR"
		}

		plainRows = append(plainRows, []string{
			fileName,
			humanize.Comma(summary.auditRecordCount),
			humanize.Bytes(uint64(summary.inputFileSize)),
			humanize.Bytes(uint64(summary.outputTotalSize)),
			summary.processingTime.Round(time.Millisecond).String(),
			status,
		})
	}

	// Add totals row without color codes
	plainRows = append(plainRows, []string{
		"TOTAL",
		humanize.Comma(totalAuditRecords),
		humanize.Bytes(uint64(totalInputSize)),
		humanize.Bytes(uint64(totalOutputSize)),
		totalProcessingTime.Round(time.Millisecond).String(),
		"",
	})

	// Write table to log file using a buffer to capture output
	var buf bytes.Buffer
	tui.Table(&buf, headers, plainRows)
	_, err = summaryFile.WriteString(buf.String())
	if err != nil {
		fmt.Printf("Warning: failed to write summary table: %v\n", err)
		return
	}

	// Write error details to log file
	if len(fileErrors) > 0 {
		fmt.Fprintf(summaryFile, "\nErrors Encountered:\n")
		fmt.Fprintf(summaryFile, "================================================================================\n")
		for i, fe := range fileErrors {
			fmt.Fprintf(summaryFile, "%d. %s\n", i+1, filepath.Base(fe.filename))
			fmt.Fprintf(summaryFile, "   Error: %v\n\n", fe.err)
		}
	} else {
		fmt.Fprintf(summaryFile, "\nAll files processed successfully!\n")
	}

	fmt.Printf("\n%sSummary table written to: %s%s\n", ansi.Green, summaryLogPath, ansi.Reset)
}

// Run parses the subcommand flags and handles the arguments.
func Run() {

	// parse commandline flags
	fs.Usage = printUsage

	err := fs.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	// Initialize web UI server if requested
	var webUIServer *webui.Server
	if *flagHTTP != "" {
		// Will be started later after we know the input files and output directory
		defer func() {
			if webUIServer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				webUIServer.Stop(ctx)
			}
		}()
	}

	// Start pprof HTTP server if requested
	if *flagPprof != "" {
		go func() {
			fmt.Printf("Starting pprof HTTP server on %s\n", *flagPprof)
			fmt.Println("Access profiling endpoints:")
			fmt.Printf("  - Goroutine profile: http://%s/debug/pprof/goroutine?debug=2\n", *flagPprof)
			fmt.Printf("  - Heap profile:      http://%s/debug/pprof/heap\n", *flagPprof)
			fmt.Printf("  - CPU profile:       http://%s/debug/pprof/profile\n", *flagPprof)
			fmt.Printf("  - All profiles:      http://%s/debug/pprof/\n", *flagPprof)
			if err := http.ListenAndServe(*flagPprof, nil); err != nil {
				log.Printf("pprof server error: %v\n", err)
			}
		}()
	}

	// Collect any unparsed arguments as potential input files (for shell-expanded wildcards)
	// When user runs: net capture -read *.pcap -out /tmp/out
	// The shell expands to: net capture -read file1.pcap file2.pcap file3.pcap -out /tmp/out
	// fs.Args() will contain the extra files: [file2.pcap, file3.pcap]
	var additionalFiles []string
	for _, arg := range fs.Args() {
		// Check if it's a regular file (not a directory)
		info, err := os.Stat(arg)
		if err != nil || info.IsDir() {
			// Skip directories and inaccessible files
			continue
		}

		// Only accept files with .pcap or .pcapng extension
		if strings.HasSuffix(strings.ToLower(arg), ".pcap") || strings.HasSuffix(strings.ToLower(arg), ".pcapng") {
			additionalFiles = append(additionalFiles, arg)
		}
	}

	if *flagGenerateConfig {
		io.GenerateConfig(fs, "capture")

		return
	}

	// print a markdown overview of all available decoders and fields
	if *flagPrintProtocolOverview {
		packet.MarkdownOverview()

		return
	}

	if *flagListInterfaces {
		utils.ListAllNetworkInterfaces()

		return
	}

	// configure CPU profiling
	if *flagCPUProfile {
		defer func() func() {
			if *flagCPUProfile {
				f, errCPUProfile := os.Create("netcap-" + netcap.Version + ".cpu.profile")
				if errCPUProfile != nil {
					log.Fatalf("could not open cpu profile file %q, error: %s\n", "netcap.cpu.profile", errCPUProfile)
				}

				if errCPUProfile = pprof.StartCPUProfile(f); errCPUProfile != nil {
					log.Fatalf("failed to start CPU profiling, error: %s\n", errCPUProfile)
				}

				return func() {
					pprof.StopCPUProfile()

					errCPUProfile = f.Close()
					if errCPUProfile != nil {
						panic("failed to write CPU profile: " + errCPUProfile.Error())
					}
				}
			}

			return func() {}
		}()

		// fgprof allows to analyze On-CPU as well as Off-CPU (e.g. I/O) time
		http.DefaultServeMux.Handle("/debug/fgprof", fgprof.Handler())

		go func() {
			log.Println(http.ListenAndServe(":6060", nil))
		}()
	}

	// print decoders and exit
	if *flagDecoders {
		packet.ShowDecoders(true)

		return
	}

	// live mode?
	var live bool
	if *flagInterface != "" {
		live = true
	}

	// set data source
	var source string
	switch {
	case *flagInput != "":
		source = *flagInput
	case *flagInterface != "":
		source = *flagInterface
	default:
		source = "unknown"
	}

	if *flagReassemblyDebug {
		reassembly.Debug = true
	}

	var elasticAddrs []string
	if *flagElasticAddrs != "" {
		elasticAddrs = strings.Split(*flagElasticAddrs, ",")
	}

	if *flagGenerateElasticIndices {
		generateElasticIndices(elasticAddrs)

		return
	}

	// abort if there is no input or no live capture
	if *flagInput == "" && !live {
		printHeader()
		fmt.Println(ansi.Red + "> nothing to do. need a pcap file with the read flag (-read) or live mode and an interface (-iface)" + ansi.Reset)
		os.Exit(1)
	}

	if strings.HasSuffix(*flagInput, defaults.FileExtensionCompressed) || strings.HasSuffix(*flagInput, defaults.FileExtension) {
		printHeader()
		fmt.Println(ansi.Red + "> the capture tool is used to create audit records from live traffic or a pcap dumpfile" + ansi.Reset)
		fmt.Println(ansi.Red + "> use the dump tool to read netcap audit records" + ansi.Reset)
		os.Exit(1)
	}

	// Check if input contains wildcards and expand to multiple files
	// Also handle shell-expanded arguments (multiple files passed on command line)
	var inputFiles []string
	if !live && *flagInput != "" {
		inputFiles, err = expandPcapFiles(*flagInput)
		if err != nil {
			log.Fatal("failed to expand input pattern: ", err)
		}

		// Add any additional files from shell expansion
		// These come from fs.Args() when shell expands *.pcap before passing to the program
		inputFiles = append(inputFiles, additionalFiles...)

		// Remove duplicates (in case first file is in both places)
		inputFiles = uniqueFiles(inputFiles)

		if len(inputFiles) == 0 {
			printHeader()
			fmt.Println(ansi.Red + "> no valid pcap or pcapng files found to process" + ansi.Reset)
			fmt.Println(ansi.Red + "> directories and non-pcap files were filtered out" + ansi.Reset)
			os.Exit(1)
		}

		if len(inputFiles) > 1 {
			fmt.Printf("Found %d pcap files to process\n", len(inputFiles))
		}
	}

	var exportMetrics bool
	if *flagMetricsAddr != "" {
		metrics.ServeMetricsAt(*flagMetricsAddr, nil)
		// TODO: make the packet metrics configurable separately, for performance analysis it is faster to only use the core metrics
		// exportMetrics = true
	}

	var numEpochs int
	var analyzerLogFileHandles []*os.File

	// Store original output directory to create subdirectories for each file
	originalOutDir := *flagOutDir

	// Start web UI server if requested (for non-live captures)
	if *flagHTTP != "" && !live {
		// For multi-file processing, use the original directory; it will be updated per file
		// For single-file processing, use the specified directory
		initialOutDir := *flagOutDir
		if len(inputFiles) > 1 {
			initialOutDir = originalOutDir
		}

		// If output directory is empty, use current working directory
		if initialOutDir == "" {
			var err error
			initialOutDir, err = os.Getwd()
			if err != nil {
				log.Printf("Failed to get working directory: %v\n", err)
				initialOutDir = "."
			}
		}

		webUIServer = webui.NewServer(*flagHTTP, initialOutDir, inputFiles, *flagHTTPAssets)
		if err := webUIServer.Start(); err != nil {
			log.Printf("Failed to start web UI server: %v\n", err)
		} else {
			fmt.Printf("\n%sWeb UI available at: %s%s\n\n", ansi.Green, webUIServer.GetURL(), ansi.Reset)
		}
	}

	if *flagAnalyzer != "" {

		alert.InitSocket()

		// update config for plugins
		*flagCompress = false
		*flagBuffer = false
		*flagCSV = true
		*flagUNIX = true

		// disable reassembly for now.
		*flagReassembleConnections = false

		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// get config path
		dir := os.Getenv(env.AnalyzerDirectory)

		analyzers := strings.Split(*flagAnalyzer, ",")
		for _, a := range analyzers {

			conf := analyze.ParseConfig(filepath.Join(dir, a+".yml"))
			if conf.WorkDir != "" {

				numEpochs = conf.Epochs

				if strings.Contains(conf.WorkDir, "~") || strings.Contains(conf.WorkDir, "$HOME") {
					dirname, err := os.UserHomeDir()
					if err != nil {
						log.Fatal(err)
					}

					conf.WorkDir = strings.Replace(conf.WorkDir, "~", dirname, 1)
					conf.WorkDir = strings.Replace(conf.WorkDir, "$HOME", dirname, 1)
				}

				err = os.Chdir(conf.WorkDir)
				if err != nil {
					log.Fatal(err)
				}
			}

			logPath := "/tmp/" + a + ".log"
			logfile, err := os.Create(logPath)
			if err != nil {
				log.Fatal(err)
			}
			analyzerLogFileHandles = append(analyzerLogFileHandles, logfile)

			fmt.Println("logfile for analyzer:", logPath)

			// create call
			cmd := exec.Command(conf.Command, conf.Args...)
			fmt.Println("invoking analyzer:", cmd.Args)

			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH=/usr/local/cuda/lib64/")

			if *flagDebug {
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
			} else {
				cmd.Stdout = logfile
				cmd.Stderr = logfile
			}

			// TODO: handle audit records from config.
			// For now it must be manually configured via CLI flags which audit records get produced.

			// start process
			errCmd := cmd.Start()
			if errCmd != nil {
				log.Println(errCmd)
			}

			// give it some time to open the socket
			time.Sleep(3 * time.Second)

			go func() {
				// wait for process
				errCmd = cmd.Wait()
				if errCmd != nil {
					log.Println(errCmd)
				}

				fmt.Println("process finished", cmd.Args)

				// TODO: make configurable
				os.Exit(0)
			}()
		}

		// switch back to current dir
		err = os.Chdir(wd)
		if err != nil {
			log.Fatal(err)
		}
	}

	// init collector
	c := collector.New(collector.Config{
		Workers:               *flagWorkers,
		PacketBufferSize:      *flagPacketBuffer,
		WriteUnknownPackets:   !*flagIgnoreUnknown,
		Promisc:               *flagPromiscMode,
		SnapLen:               *flagSnapLen,
		BaseLayer:             utils.GetBaseLayer(*flagBaseLayer),
		DecodeOptions:         utils.GetDecodeOptions(*flagDecodeOptions),
		DPI:                   *flagDPI,
		DPIModules:            *flagDPIModules,
		ReassembleConnections: *flagReassembleConnections,
		FreeOSMem:             *flagFreeOSMemory,
		LogErrors:             *flagLogErrors,
		NoPrompt:              *flagYes,
		HTTPShutdownEndpoint:  *flagHTTPShutdown,
		Timeout:               *flagTimeout,
		Labels:                *flagLabels,
		Scatter:               *flagScatter,
		ScatterDuration:       *flagScatterDuration,
		DecoderConfig: &config.Config{
			Quiet:         *flagQuiet,
			PrintProgress: *flagPrintProgress,
			Buffer:        *flagBuffer,
			MemBufferSize: *flagMemBufferSize,
			Compression:   *flagCompress,
			CSV:           *flagCSV,
			UnixSocket:    *flagUNIX,
			Encode:        *flagEncode,
			Label:         *flagLabels != "",
			Null:          *flagNull,
			Elastic:       *flagElastic,
			ElasticConfig: io.ElasticConfig{
				ElasticAddrs:   elasticAddrs,
				ElasticUser:    *flagElasticUser,
				ElasticPass:    *flagElasticPass,
				KibanaEndpoint: *flagKibanaEndpoint,
			},
			BulkSizeGoPacket:               *flagBulkSizeGoPacket,
			BulkSizeCustom:                 *flagBulkSizeCustom,
			IncludeDecoders:                *flagInclude,
			ExcludeDecoders:                *flagExclude,
			Out:                            *flagOutDir,
			Proto:                          *flagProto,
			JSON:                           *flagJSON,
			Chan:                           false,
			Source:                         source,
			IncludePayloads:                *flagPayload,
			ExportMetrics:                  exportMetrics,
			AddContext:                     *flagContext,
			FlushEvery:                     *flagFlushevery,
			DefragIPv4:                     *flagDefragIPv4,
			Checksum:                       *flagChecksum,
			NoOptCheck:                     *flagNooptcheck,
			IgnoreFSMerr:                   *flagIgnorefsmerr,
			AllowMissingInit:               *flagAllowmissinginit,
			Debug:                          *flagDebug,
			HexDump:                        *flagHexdump,
			WaitForConnections:             *flagWaitForConnections,
			WriteIncomplete:                *flagWriteincomplete,
			MemProfile:                     *flagMemprofile,
			ConnFlushInterval:              *flagConnFlushInterval,
			ConnTimeOut:                    *flagConnTimeOut,
			FlowFlushInterval:              *flagFlowFlushInterval,
			FlowTimeOut:                    *flagFlowTimeOut,
			CloseInactiveTimeOut:           *flagCloseInactiveTimeout,
			ClosePendingTimeOut:            *flagClosePendingTimeout,
			FileStorage:                    *flagFileStorage,
			CalculateEntropy:               *flagCalcEntropy,
			SaveConns:                      *flagSaveConns,
			TCPDebug:                       *flagTCPDebug,
			UseRE2:                         *flagUseRE2,
			BannerSize:                     *flagBannerSize,
			StreamDecoderBufSize:           *flagStreamDecoderBufSize,
			HarvesterBannerSize:            *flagHarvesterBannerSize,
			StopAfterHarvesterMatch:        *flagStopAfterHarvesterMatch,
			StopAfterServiceProbeMatch:     *flagStopAfterServiceProbeMatch,
			StopAfterServiceCategoryMiss:   *flagStopAfterServiceCategoryMiss,
			CustomRegex:                    *flagCustomCredsRegex,
			StreamBufferSize:               *flagStreamBufferSize,
			NumStreamWorkers:               *flagNumStreamWorkers,
			MaxStreamBytes:                 *flagMaxStreamBytes,
			MaxBufferedPagesPerConnection:  *flagMaxBufferedPagesPerConnection,
			MaxBufferedPagesTotal:          *flagMaxBufferedPagesTotal,
			IgnoreDecoderInitErrors:        *flagIgnoreInitErrs,
			DisableGenericVersionHarvester: *flagDisableGenericVersionHarvester,
			RemoveClosedStreams:            *flagRemoveClosedStreams,
			CompressionBlockSize:           *flagCompressionBlockSize,
			CompressionLevel:               getCompressionLevel(*flagCompressionLevel),
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:    *flagReverseDNS,
			LocalDNS:      *flagLocalDNS,
			MACDB:         *flagMACDB,
			Ja3DB:         *flagJa3DB,
			ServiceDB:     *flagServiceDB,
			GeolocationDB: *flagGeolocationDB,
		},
	})
	c.Bpf = *flagBPF
	c.InputFile = *flagInput
	c.PrintTime = *flagTime
	c.Epochs = numEpochs

	if len(analyzerLogFileHandles) > 0 {
		for _, f := range analyzerLogFileHandles {
			c.CloseFileHandleOnShutdown(f)
		}
	}

	c.PrintConfiguration()

	// collect traffic live from named interface
	if live {
		err = c.CollectLive(*flagInterface, *flagBPF, context.Background())
		if err != nil {
			log.Fatal("failed to collect live packets: ", err)
		}

		return
	}

	// Track errors and summary statistics for each file when processing multiple files
	var fileErrors []fileError
	var fileSummaries []fileSummary

	// Process each input file
	for fileIdx, inputFile := range inputFiles {
		if len(inputFiles) > 1 {
			fmt.Printf("\n|| ================================================================== ||\n")
			fmt.Printf("   Processing file %d/%d: %s\n", fileIdx+1, len(inputFiles), inputFile)
			fmt.Printf("|| ================================================================== ||\n")

			// Reset global state from previous file
			if fileIdx > 0 {
				fmt.Println("Resetting global state...")

				// Report memory usage before cleanup
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				numGoroutines := runtime.NumGoroutine()
				fmt.Printf("Memory before cleanup: Heap Alloc=%s, Heap Sys=%s, Goroutines=%d\n",
					humanize.Bytes(m.HeapAlloc), humanize.Bytes(m.HeapSys), numGoroutines)

				// Step 1: Reset packet-level state (lightweight, no heavy allocations)
				packet.ResetDeviceProfiles()
				packet.ResetIPProfiles()
				packet.ResetConnections()

				// Step 2: Reset stream-level state (lightweight)
				service.ResetStore()
				service.ResetProbeEnums()
				udp.ResetStreams()
				httpstream.ResetHTTPStore()
				streamutils.ResetStats()

				// Step 2a: CRITICAL - Reset global caches that accumulate unbounded
				// UserAgentCache, ja3Cache, and Software Store accumulate across all files
				software.ResetCaches()

				// Step 2b: CRITICAL - Reset deduplication stores
				// These accumulate ALL unique credentials/exploits/vulns across files
				credentials.ResetCredStore()
				exploit.ResetExploitStore()
				vulnerability.ResetVulnStore()

				// Step 3: CRITICAL - Flush all assemblers to release pageCaches
				// THE ROOT CAUSE: Assembler.pageCache grows unbounded and NEVER SHRINKS
				// Each page holds AssemblerContext which references packet data
				// pageCaches can grow to GB of memory and are NOT released on collector cleanup
				// NOTE: cleanup() is already called at the end of CollectPcap(), which stops all goroutines
				// including workers, TCP stream readers, and freeOSMemory goroutine
				if c != nil {
					fmt.Println("Flushing assemblers to release pageCaches...")
					c.FlushAssemblers()
				}

				// Step 4: CRITICAL - Nil out collector to release all references
				// This breaks the reference chain: collector -> assemblers -> pageCaches -> packets
				c = nil

				// Step 5: Force GC to clear assemblers, pageCaches, and packet data
				// This is CRITICAL - we must GC everything before resetting the TCP factory
				runtime.GC()

				// Step 6: CRITICAL - Ensure ALL TCP stream reader goroutines are stopped
				// Even though cleanup() was called at the end of CollectPcap(), we need to
				// ensure goroutines have fully exited before resetting the factory
				// Use quiet version since log files for previous file are already closed
				fmt.Println("Ensuring TCP stream readers are stopped...")
				tcp.CloseStreamReaderChannelsAndWaitQuiet()

				// Step 7: NOW reset TCP factory - old StreamPool can be GC'd
				// Because assemblers, pageCaches, and stream readers are gone, old pool has no references
				tcp.ResetStreamFactory()

				// Step 8: Reset DPI flow tracker if DPI is enabled
				if *flagDPI {
					dpi.Reset(*flagDPIModules)
				}

				// Step 9: Final GC and OS memory release
				runtime.GC()
				debug.FreeOSMemory()

				// Report memory usage after cleanup
				runtime.ReadMemStats(&m)
				numGoroutines = runtime.NumGoroutine()
				fmt.Printf("Memory after cleanup: Heap Alloc=%s, Heap Sys=%s, Goroutines=%d\n",
					humanize.Bytes(m.HeapAlloc), humanize.Bytes(m.HeapSys), numGoroutines)
			}

			// Set output directory for this specific file
			*flagOutDir = getOutputDirForFile(inputFile, originalOutDir)
			fmt.Printf("Output directory: %s\n", *flagOutDir)

			// Update web UI server with new output directory
			if webUIServer != nil {
				webUIServer.UpdateOutputDir(*flagOutDir)
			}

			// Mark previous file as completed if this is not the first file
			if webUIServer != nil && fileIdx > 0 {
				webUIServer.MarkFileCompleted(inputFiles[fileIdx-1])
			}

			// Create a fresh collector instance with updated configuration for this file
			c = collector.New(collector.Config{
				Workers:               *flagWorkers,
				PacketBufferSize:      *flagPacketBuffer,
				WriteUnknownPackets:   !*flagIgnoreUnknown,
				Promisc:               *flagPromiscMode,
				SnapLen:               *flagSnapLen,
				BaseLayer:             utils.GetBaseLayer(*flagBaseLayer),
				DecodeOptions:         utils.GetDecodeOptions(*flagDecodeOptions),
				DPI:                   *flagDPI,
				DPIModules:            *flagDPIModules,
				ReassembleConnections: *flagReassembleConnections,
				FreeOSMem:             *flagFreeOSMemory,
				LogErrors:             *flagLogErrors,
				NoPrompt:              *flagYes,
				HTTPShutdownEndpoint:  false, // Disable for multi-file processing
				Timeout:               *flagTimeout,
				Labels:                *flagLabels,
				Scatter:               *flagScatter,
				ScatterDuration:       *flagScatterDuration,
				DecoderConfig: &config.Config{
					Quiet:         *flagQuiet,
					PrintProgress: *flagPrintProgress,
					Buffer:        *flagBuffer,
					MemBufferSize: *flagMemBufferSize,
					Compression:   *flagCompress,
					CSV:           *flagCSV,
					UnixSocket:    *flagUNIX,
					Encode:        *flagEncode,
					Label:         *flagLabels != "",
					Null:          *flagNull,
					Elastic:       *flagElastic,
					ElasticConfig: io.ElasticConfig{
						ElasticAddrs:   elasticAddrs,
						ElasticUser:    *flagElasticUser,
						ElasticPass:    *flagElasticPass,
						KibanaEndpoint: *flagKibanaEndpoint,
					},
					BulkSizeGoPacket:               *flagBulkSizeGoPacket,
					BulkSizeCustom:                 *flagBulkSizeCustom,
					IncludeDecoders:                *flagInclude,
					ExcludeDecoders:                *flagExclude,
					Out:                            *flagOutDir,
					Proto:                          *flagProto,
					JSON:                           *flagJSON,
					Chan:                           false,
					Source:                         inputFile,
					IncludePayloads:                *flagPayload,
					ExportMetrics:                  exportMetrics,
					AddContext:                     *flagContext,
					FlushEvery:                     *flagFlushevery,
					DefragIPv4:                     *flagDefragIPv4,
					Checksum:                       *flagChecksum,
					NoOptCheck:                     *flagNooptcheck,
					IgnoreFSMerr:                   *flagIgnorefsmerr,
					AllowMissingInit:               *flagAllowmissinginit,
					Debug:                          *flagDebug,
					HexDump:                        *flagHexdump,
					WaitForConnections:             *flagWaitForConnections,
					WriteIncomplete:                *flagWriteincomplete,
					MemProfile:                     *flagMemprofile,
					ConnFlushInterval:              *flagConnFlushInterval,
					ConnTimeOut:                    *flagConnTimeOut,
					FlowFlushInterval:              *flagFlowFlushInterval,
					FlowTimeOut:                    *flagFlowTimeOut,
					CloseInactiveTimeOut:           *flagCloseInactiveTimeout,
					ClosePendingTimeOut:            *flagClosePendingTimeout,
					FileStorage:                    *flagFileStorage,
					CalculateEntropy:               *flagCalcEntropy,
					SaveConns:                      *flagSaveConns,
					TCPDebug:                       *flagTCPDebug,
					UseRE2:                         *flagUseRE2,
					BannerSize:                     *flagBannerSize,
					StreamDecoderBufSize:           *flagStreamDecoderBufSize,
					HarvesterBannerSize:            *flagHarvesterBannerSize,
					StopAfterHarvesterMatch:        *flagStopAfterHarvesterMatch,
					StopAfterServiceProbeMatch:     *flagStopAfterServiceProbeMatch,
					StopAfterServiceCategoryMiss:   *flagStopAfterServiceCategoryMiss,
					CustomRegex:                    *flagCustomCredsRegex,
					StreamBufferSize:               *flagStreamBufferSize,
					NumStreamWorkers:               *flagNumStreamWorkers,
					MaxStreamBytes:                 *flagMaxStreamBytes,
					MaxBufferedPagesPerConnection:  *flagMaxBufferedPagesPerConnection,
					MaxBufferedPagesTotal:          *flagMaxBufferedPagesTotal,
					IgnoreDecoderInitErrors:        *flagIgnoreInitErrs,
					DisableGenericVersionHarvester: *flagDisableGenericVersionHarvester,
					RemoveClosedStreams:            *flagRemoveClosedStreams,
					CompressionBlockSize:           *flagCompressionBlockSize,
					CompressionLevel:               getCompressionLevel(*flagCompressionLevel),
				},
				ResolverConfig: resolvers.Config{
					ReverseDNS:    *flagReverseDNS,
					LocalDNS:      *flagLocalDNS,
					MACDB:         *flagMACDB,
					Ja3DB:         *flagJa3DB,
					ServiceDB:     *flagServiceDB,
					GeolocationDB: *flagGeolocationDB,
				},
			})
			c.Bpf = *flagBPF
			c.InputFile = inputFile
			c.PrintTime = *flagTime
			c.Epochs = numEpochs

			c.PrintConfiguration()
		}

		// start timer
		start := time.Now()

		// Final safety check: ensure input is a file, not a directory
		fileInfo, err := os.Stat(inputFile)
		if err != nil {
			fmt.Printf("Error: cannot access file %s: %v\n", inputFile, err)
			if len(inputFiles) > 1 {
				fmt.Println("Skipping to next file...")
				continue
			}
			os.Exit(1)
		}
		if fileInfo.IsDir() {
			fmt.Printf("Error: %s is a directory, not a file\n", inputFile)
			if len(inputFiles) > 1 {
				fmt.Println("Skipping to next file...")
				continue
			}
			os.Exit(1)
		}

		// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
		// setting BPF filters is not yet supported by the pcapgo package
		if *flagBPF != "" {
			if err = c.CollectBPF(inputFile, *flagBPF); err != nil {
				if len(inputFiles) > 1 {
					fmt.Printf("Error: failed to set BPF: %v\n", err)
					fileErrors = append(fileErrors, fileError{filename: inputFile, err: fmt.Errorf("failed to set BPF: %w", err)})
					fmt.Println("Skipping to next file...")
					continue
				}
				log.Fatal("failed to set BPF: ", err)
			}

			continue
		}

		// if not, use native pcapgo version
		isPcap, err := collector.IsPcap(inputFile)
		if err != nil {
			// invalid path
			if len(inputFiles) > 1 {
				fmt.Printf("Error: failed to open file: %v\n", err)
				fileErrors = append(fileErrors, fileError{filename: inputFile, err: fmt.Errorf("failed to open file: %w", err)})
				fmt.Println("Skipping to next file...")
				continue
			}
			fmt.Println("failed to open file:", err)
			os.Exit(1)
		}

		if isPcap {
			if err = c.CollectPcap(inputFile); err != nil {
				if len(inputFiles) > 1 {
					fmt.Printf("Error: failed to collect audit records from pcap file: %v\n", err)
					fileErrors = append(fileErrors, fileError{filename: inputFile, err: fmt.Errorf("failed to collect audit records from pcap file: %w", err)})
					fmt.Println("Skipping to next file...")
					continue
				}
				log.Fatal("failed to collect audit records from pcap file: ", err)
			}
		} else {
			if err = c.CollectPcapNG(inputFile); err != nil {
				if len(inputFiles) > 1 {
					fmt.Printf("Error: failed to collect audit records from pcapng file: %v\n", err)
					fileErrors = append(fileErrors, fileError{filename: inputFile, err: fmt.Errorf("failed to collect audit records from pcapng file: %w", err)})
					fmt.Println("Skipping to next file...")
					continue
				}
				log.Fatal("failed to collect audit records from pcapng file: ", err)
			}
		}

		if *flagTime {
			// stat input file
			stat, _ := os.Stat(inputFile)
			fmt.Println("size", humanize.Bytes(uint64(stat.Size())), "done in", time.Since(start))
		}

		if *flagPPS {
			c.RenderPacketsPerSecond(inputFile, *flagOutDir)
		}

		// Force cleanup after processing each file to reset state
		if len(inputFiles) > 1 {
			fmt.Printf("\nCompleted processing: %s\n", inputFile)

			// Collect summary statistics for this file
			summary := fileSummary{
				filename:        inputFile,
				inputFileSize:   fileInfo.Size(),
				outputTotalSize: c.GetTotalBytesWritten(),
				processingTime:  time.Since(start),
				err:             nil,
			}

			// Count total audit records from all decoders
			summary.auditRecordCount = c.GetTotalAuditRecords()

			// If there was an error for this file, add it to the summary
			for _, fe := range fileErrors {
				if fe.filename == inputFile {
					summary.err = fe.err
					break
				}
			}

			fileSummaries = append(fileSummaries, summary)
		}
	}

	// Print detailed summary table for multi-file mode
	if len(inputFiles) > 1 {
		writeSummaryTable(inputFiles, fileSummaries, fileErrors, originalOutDir)
	}

	// memory profiling (after all files processed)
	if *flagMemProfile {
		f, errProfile := os.Create("netcap-" + netcap.Version + ".mem.profile")
		if errProfile != nil {
			log.Fatal("failed create memory profile: ", errProfile)
		}

		if errProfile = pprof.WriteHeapProfile(f); errProfile != nil {
			log.Fatal("failed to write heap profile: ", errProfile)
		}

		err = f.Close()
		if err != nil {
			panic("failed to write memory profile: " + err.Error())
		}
	}

	// If web UI server is running, mark processing as complete and wait for interrupt
	if webUIServer != nil {
		// Mark the last file as completed
		if len(inputFiles) > 0 {
			webUIServer.MarkFileCompleted(inputFiles[len(inputFiles)-1])
		}
		webUIServer.SetProcessingComplete()

		fmt.Printf("\n%s========================================%s\n", ansi.Green, ansi.Reset)
		fmt.Printf("%sProcessing complete!%s\n", ansi.Green, ansi.Reset)
		fmt.Printf("Web UI available at: %s%s%s\n", ansi.Cyan, webUIServer.GetURL(), ansi.Reset)
		fmt.Printf("Press %sCtrl+C%s to stop the server and exit\n", ansi.Yellow, ansi.Reset)
		fmt.Printf("%s========================================%s\n\n", ansi.Green, ansi.Reset)

		// Setup signal handler for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		// Wait for interrupt signal
		<-sigChan

		fmt.Println("\nShutting down web UI server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := webUIServer.Stop(ctx); err != nil {
			log.Printf("Error stopping web UI server: %v\n", err)
		}

		fmt.Println("Server stopped. Goodbye!")
	}
}

func generateElasticIndices(elasticAddrs []string) {

	start := time.Now()

	packet.ApplyActionToPacketDecodersAsync(func(d packet.DecoderAPI) {
		io.CreateElasticIndex(makeWriterConfig(d.GetName(), d.GetType(), elasticAddrs))
	})

	packet.ApplyActionToGoPacketDecodersAsync(func(d *packet.GoPacketDecoder) {
		io.CreateElasticIndex(makeWriterConfig(d.Layer.String(), d.Type, elasticAddrs))
	})

	stream.ApplyActionToStreamDecodersAsync(func(d core.StreamDecoderAPI) {
		io.CreateElasticIndex(makeWriterConfig(d.GetName(), d.GetType(), elasticAddrs))
	})

	stream.ApplyActionToAbstractDecodersAsync(func(d core.DecoderAPI) {
		io.CreateElasticIndex(makeWriterConfig(d.GetName(), d.GetType(), elasticAddrs))
	})

	fmt.Println("done in", time.Since(start))
}

func makeWriterConfig(name string, typ types.Type, elasticAddrs []string) *io.WriterConfig {
	return &io.WriterConfig{
		UnixSocket: *flagUNIX,
		CSV:        *flagCSV,
		Proto:      *flagProto,
		JSON:       *flagJSON,
		Name:       name,
		Type:       typ,
		Null:       *flagNull,
		Elastic:    *flagElastic,
		ElasticConfig: io.ElasticConfig{
			ElasticAddrs:   elasticAddrs,
			ElasticUser:    *flagElasticUser,
			ElasticPass:    *flagElasticPass,
			KibanaEndpoint: *flagKibanaEndpoint,
			BulkSize:       *flagBulkSizeCustom,
		},
		Buffer:        *flagBuffer,
		Compress:      *flagCompress,
		Out:           *flagOutDir,
		Chan:          false,
		ChanSize:      0,
		MemBufferSize: *flagMemBufferSize,
		Version:       netcap.Version,
		StartTime:     time.Now(),
	}
}
