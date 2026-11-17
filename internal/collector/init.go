package collector

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/dreadl0ck/netcap/internal/label/manager"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/decoder/stream"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/exploit"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/vulnerability"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/deviceprofile"
	"github.com/dreadl0ck/netcap/internal/dnscontext"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/tlsdecrypt"
	"github.com/dreadl0ck/netcap/types"
)

var (
	errAborted        = errors.New("operation aborted by user")
	errNotInteractive = errors.New("cannot prompt for overwrite")
)

// Init sets up the collector and starts the configured number of workers
// must be called prior to usage of the collector instance.
func (c *Collector) Init() (err error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleStopped {
		return ErrStopped
	}
	if c.initialized {
		return nil
	}
	if _, err := decoderutils.SelectDecoders([]string(nil), c.config.DecoderConfig.IncludeDecoders, c.config.DecoderConfig.ExcludeDecoders, func(name string) string { return name }, packet.ErrInvalidDecoder); err != nil {
		return fmt.Errorf("decoder selection: %w", err)
	}
	if path := c.config.DecoderConfig.LinkProfilesPath; path != "" {
		c.linkProfiles, err = deviceprofile.Load(path)
		if err != nil {
			return fmt.Errorf("link profiles: %w", err)
		}
	}
	c.outputReplacement, err = c.prepareOutputReplacement()
	if err != nil {
		return err
	}
	if c.config.DecoderConfig.MaxRetainedTCPBytes < 0 {
		return fmt.Errorf("max-retained-tcp-bytes cannot be negative")
	}
	if c.config.DecoderConfig.MaxAggregateStateBytes < 0 {
		return fmt.Errorf("max-aggregate-state-bytes cannot be negative")
	}
	if c.config.DecoderConfig.LocalReassemblyPageLoss && (c.captureKind != "file" || c.config.DecoderConfig.IncrementalHTTP || c.config.DecoderConfig.MaxRetainedReassemblyBytes <= 0) {
		return fmt.Errorf("local TCP page loss requires offline capture with a positive page budget and incremental HTTP disabled")
	}
	c.contextLocked()
	c.streamStateBudget, err = core.NewStateBudget(c.config.DecoderConfig.MaxRetainedTCPStateBytes, c.runCancel)
	if err != nil {
		return err
	}
	if !c.config.DecoderConfig.IncrementalHTTP && c.config.DecoderConfig.MaxRetainedTCPStateBytes == 0 {
		c.streamStateBudget = nil
	}
	tcp.ConfigureIncrementalState(c.streamStateBudget, c.runCancel)
	if c.config.DecoderConfig.LocalReassemblyPageLoss {
		c.reassemblyPageBudget, err = reassembly.NewLocalPageBudget(c.config.DecoderConfig.MaxRetainedReassemblyBytes)
	} else {
		c.reassemblyPageBudget, err = reassembly.NewPageBudget(c.config.DecoderConfig.MaxRetainedReassemblyBytes, c.runCancel)
	}
	if err != nil {
		return err
	}
	if err := tcp.ConfigureRetainedPayloadBudget(c.config.DecoderConfig.MaxRetainedTCPBytes, c.runCancel); err != nil {
		return err
	}
	// set configuration for decoder pkgs
	if c.captureKind != "file" || c.config.DecoderConfig.TLSSecrets == nil {
		c.config.DecoderConfig.TLSSecrets = tlsdecrypt.NewSecrets()
	}
	c.config.DecoderConfig.PerfTracker = c.perfTracker
	packet.SetConfig(c.config.DecoderConfig)

	// Wire up device enrichment callback for network discovery protocols
	streamutils.DeviceEnricher = func(ip string, hostnames, deviceTypes, roles []string, os string) {
		c.analysisMu.Lock()
		if bound, ok := c.ipScopes[ip]; ok && !bound.Ambiguous && c.hostIdentity != nil {
			c.hostIdentity.Discover(bound.Key, ip, hostnames)
		}
		c.analysisMu.Unlock()
		if dp := packet.DeviceProfiles.FindByIP(ip); dp != nil {
			dp.EnrichFromDiscovery(hostnames, deviceTypes, roles, os)
		}
	}

	decoderconfig.Instance = c.config.DecoderConfig
	stream.Debug = c.config.DecoderConfig.Debug
	if c.config.Labels != "" {
		lm := manager.NewLabelManager(false, false, false, c.config.Scatter, c.config.ScatterDuration)
		// Set Debug before Init so verbose logging during mapping load is honored.
		lm.Debug = c.config.DecoderConfig.Debug
		lm.Init(c.config.Labels)
		c.config.DecoderConfig.LabelManager = lm
	}

	// create state machine options
	tcp.StreamFactory.FSMOptions = reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: c.config.DecoderConfig.AllowMissingInit,
	}

	// init logfile if necessary
	if c.netcapLogFile == nil {
		err = c.initLogging()
		if err != nil {
			return err
		}
	}

	// Log signal handling status after logger is initialized
	if c.config.NoSignalHandling {
		c.log.Info("signal handling disabled (NoSignalHandling=true) - parent process will handle signals")
	}

	// create full output directory path if set
	if c.config.DecoderConfig.Out != "" {
		err = os.MkdirAll(c.config.DecoderConfig.Out, c.config.OutDirPermission)
		if err != nil {
			return err
		}
	}

	// init deep packet inspection
	c.config.DecoderConfig.AggregateStore = nil
	if c.config.DecoderConfig.MaxAggregateStateBytes > 0 {
		c.config.DecoderConfig.AggregateStore, err = aggregate.Open(c.config.DecoderConfig.Out, c.config.DecoderConfig.MaxAggregateStateBytes, c.runCancel)
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				err = errors.Join(err, c.config.DecoderConfig.AggregateStore.Close())
				c.config.DecoderConfig.AggregateStore = nil
			}
		}()
		packet.ResetConnections()
		packet.ResetHosts()
		packet.ResetDeviceProfiles()
		service.ResetStore()
		software.ResetCaches()
		vulnerability.ResetVulnStore()
		exploit.ResetExploitStore()
	}
	if err := file.StartAnalysis(c.config.DecoderConfig.Out, ""); err != nil {
		return fmt.Errorf("artifact analysis admission: %w", err)
	}
	c.artifactAnalysisStarted.Store(true)
	if c.config.DPI {
		c.printlnStdOut("initializing dpi libs")
		dpi.InitWithConfig(c.config.DPIModules, dpi.RuntimeConfig{Workers: c.config.DPIWorkers})
	}

	// initialize resolvers
	resolvers.SetPerfTracker(c.perfTracker)
	resolvers.Init(c.config.ResolverConfig, c.config.DecoderConfig.Quiet)

	// print database load confirmation in debug mode
	if c.config.DecoderConfig.Debug {
		c.printlnStdOut("loaded netcap databases from", resolvers.DataBaseFolderPath)
	}

	if c.config.ResolverConfig.LocalDNS {
		packet.LocalDNS = true
	}

	c.printStdOut("initializing decoders... ")
	if err = c.initNetworkDetection(); err != nil {
		return fmt.Errorf("network detection: %w", err)
	}
	if c.config.DNSResolutionContext {
		c.dnsContext = dnscontext.New()
	} else {
		c.dnsContext = nil
	}
	c.netcapLog.Println("initializing decoders... ")

	if c.config.DecoderConfig.ExportMetrics {
		for i, m := range types.Metrics {
			err = prometheus.Register(m)
			if err != nil {
				return fmt.Errorf("register decoder metrics %d: %w", i, err)
			}
		}
	}

	encoder.SetConfig(&encoder.Config{
		//MinMax: true,
		ZScore: true,
		//NormalizeCategoricals: true,
	})

	var (
		start = time.Now()
		wg    sync.WaitGroup
	)

	wg.Add(4)
	var initErrors [4]error
	abstractReady := make(chan struct{})

	go func() {
		// initialize decoders
		c.goPacketDecoders, initErrors[0] = packet.InitGoPacketDecoders(c.config.DecoderConfig)
		wg.Done()
	}()

	go func() {
		c.packetDecoders, initErrors[1] = packet.InitPacketDecoders(c.config.DecoderConfig)
		wg.Done()
	}()

	go func() {
		// Stream post-init hooks consume abstract-decoder loggers and enrichment.
		<-abstractReady
		c.streamDecoders, initErrors[2] = stream.InitDecoders(c.config.DecoderConfig)
		wg.Done()
	}()

	go func() {
		c.abstractDecoders, initErrors[3] = stream.InitAbstractDecoders(c.config.DecoderConfig)
		close(abstractReady)
		wg.Done()
	}()

	// set pointer of collectors atomic counter map in decoder pkg
	decoderutils.SetErrorMap(c.errorMap)

	// create pcap files for packets
	// with unknown protocols or errors while decoding
	unknownErr := c.createUnknownPcap()

	// create error pcap file for packets that had an error during processing
	packetErrorsErr := c.createErrorsPcap()

	// start routine to force releasing memory back to the OS in a fixed interval
	// this is meant for diagnostic purposes and should not be used in production
	if c.config.FreeOSMem != 0 {
		fmt.Println("will free the OS memory every", c.config.FreeOSMem, "minutes")
		c.backgroundWG.Add(1)
		go func() {
			defer c.backgroundWG.Done()
			c.freeOSMemory(c.runCtx)
		}()
	}

	// wait for decoder init to finish
	wg.Wait()
	if err = errors.Join(append(initErrors[:], unknownErr, packetErrorsErr)...); err != nil {
		return fmt.Errorf("initialize decoders: %w", err)
	}
	if err = c.persistServiceSignatures(); err != nil {
		return fmt.Errorf("record service signature inventory: %w", err)
	}
	c.log.Info("initialized decoders",
		zap.Int("packetDecoders", len(c.packetDecoders)),
		zap.Int("streamDecoders", len(c.streamDecoders)),
		zap.Int("goPacketDecoders", len(c.goPacketDecoders)),
		zap.Int("abstractDecoders", len(c.abstractDecoders)),
	)

	// Wrap decoders with filtering/rules if configured
	c.WrapWritersWithFiltering()

	c.buildProgressString()
	c.printlnStdOut("done in", time.Since(start))
	if err := c.initFlowExports(); err != nil {
		return err
	}
	if err := c.initCaptureEvidence(); err != nil {
		return err
	}
	runID := ""
	if c.captureEvidence != nil {
		runID = c.captureEvidence.RunID()
	}
	file.BindAnalysisRunID(runID)
	c.initWorkers()
	c.log.Info("spawned workers", zap.Int("total", c.config.Workers))
	c.initialized = true
	if !c.config.NoSignalHandling {
		c.handleSignals()
	}

	return nil
}
