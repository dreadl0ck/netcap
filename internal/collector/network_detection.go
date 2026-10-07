package collector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/gopacket/gopacket"
)

func (c *Collector) initNetworkDetection() error {
	if !c.config.NetworkDetection {
		return nil
	}
	options := networkdetect.DefaultConfig()
	if c.config.NetworkDetectionConfig != "" {
		var err error
		options, err = networkdetect.LoadConfig(c.config.NetworkDetectionConfig)
		if err != nil {
			return err
		}
	}
	engine, err := networkdetect.New(options)
	if err != nil {
		return err
	}
	writer, err := rules.NewFileAlertWriter(c.config.DecoderConfig.Out)
	if err != nil {
		return err
	}
	c.dispatchMu.Lock()
	c.networkDetector, c.networkAlertWriter = engine, writer
	c.networkDetectionError = nil
	c.dispatchMu.Unlock()
	return nil
}

func (c *Collector) observeNetworkDetection(packet gopacket.Packet) {
	if c.networkDetector == nil || c.networkDetectionError != nil {
		return
	}
	scope := networkdetect.Scope{Sensor: "local", Interface: "pcap"}
	if c.behaviorScope.Sensor != "" {
		scope.Sensor = c.behaviorScope.Sensor
	}
	if c.behaviorScope.Interface != "" {
		scope.Interface = c.behaviorScope.Interface
	}
	for _, event := range networkdetect.PacketEvents(packet, scope) {
		alerts, err := c.networkDetector.Observe(event)
		if err != nil {
			c.networkDetectionError = err
			return
		}
		for _, alert := range alerts {
			if err := c.networkAlertWriter.WriteAlert(alert); err != nil {
				c.networkDetectionError = err
				return
			}
			atomic.AddInt64(&c.alertCount, 1)
		}
	}
}

func (c *Collector) closeNetworkDetection() error {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	if c.networkDetector == nil {
		return nil
	}
	stats := c.networkDetector.Stats()
	if c.networkDetectionError != nil {
		stats.Error = c.networkDetectionError.Error()
	}
	data, err := json.MarshalIndent(stats, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(c.config.DecoderConfig.Out, networkdetect.StatsFilename), append(data, '\n'), 0600)
	}
	c.networkDetectionError = errors.Join(c.networkDetectionError, err, c.networkAlertWriter.Close())
	return c.networkDetectionError
}

func (c *Collector) GetNetworkDetectionError() error {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	return c.networkDetectionError
}

func (c *Collector) NetworkDetectionForOutput(output string) (networkdetect.Stats, bool) {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	if c.config == nil || c.networkDetector == nil || c.workersStopped {
		return networkdetect.Stats{}, false
	}
	want, err := filepath.Abs(output)
	if err != nil {
		return networkdetect.Stats{}, false
	}
	actual, err := filepath.Abs(c.config.DecoderConfig.Out)
	if err != nil || want != actual {
		return networkdetect.Stats{}, false
	}
	s := c.networkDetector.Stats()
	if c.networkDetectionError != nil {
		s.Error = c.networkDetectionError.Error()
	}
	return s, true
}
