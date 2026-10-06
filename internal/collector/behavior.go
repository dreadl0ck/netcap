package collector

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/gopacket/gopacket"
)

func (c *Collector) SetBehaviorDeliveryHealth(read func() *behavior.DeliveryHealth) {
	c.behaviorHealthMu.Lock()
	defer c.behaviorHealthMu.Unlock()
	c.behaviorDeliveryHealth = read
}

func (c *Collector) GetBehaviorHealth(output string) behavior.Health {
	c.behaviorHealthMu.Lock()
	capture := c.behaviorCaptureHealth
	readDelivery := c.behaviorDeliveryHealth
	c.behaviorHealthMu.Unlock()
	c.dispatchMu.Lock()
	engine := c.behaviorEngine
	capture.Scope = c.behaviorScope
	drops := c.behaviorQueueDrops
	capture.QueueDrops = &drops
	capture.Packets = c.behaviorPackets
	capture.Workers = len(c.workers)
	if capture.Workers == 0 {
		capture.Workers = c.numWorkers
	}
	for _, worker := range c.workers {
		capture.Queued += len(worker)
		capture.QueueCapacity += cap(worker)
	}
	if capture.QueueCapacity == 0 && c.config != nil {
		capture.QueueCapacity = c.config.PacketBufferSize * capture.Workers
	}
	c.dispatchMu.Unlock()
	var delivery *behavior.DeliveryHealth
	if readDelivery != nil {
		delivery = readDelivery()
	}
	if engine == nil {
		return behavior.Health{}
	}
	if capture.Workers == 0 {
		return engine.Health(output, nil, delivery)
	}
	return engine.Health(output, &capture, delivery)
}

// Linux packet-socket stats are deltas; libpcap stats are cumulative.
func (c *Collector) recordBehaviorCaptureStats(received, dropped uint64, delta bool, err error) {
	c.behaviorHealthMu.Lock()
	defer c.behaviorHealthMu.Unlock()
	if err != nil {
		c.behaviorCaptureHealth.StatsError = err.Error()
		return
	}
	if delta {
		if c.behaviorCaptureHealth.KernelReceived != nil {
			received += *c.behaviorCaptureHealth.KernelReceived
		}
		if c.behaviorCaptureHealth.KernelDrops != nil {
			dropped += *c.behaviorCaptureHealth.KernelDrops
		}
	}
	c.behaviorCaptureHealth.KernelReceived, c.behaviorCaptureHealth.KernelDrops = &received, &dropped
	c.behaviorCaptureHealth.StatsAt = time.Now().UnixMilli()
	c.behaviorCaptureHealth.StatsError = ""
}

func (c *Collector) BehaviorForOutput(output string) *behavior.Engine {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	if c.behaviorEngine == nil || c.config == nil || c.config.DecoderConfig == nil {
		return nil
	}
	want, err := filepath.Abs(output)
	if err != nil {
		return nil
	}
	actual, err := filepath.Abs(c.config.DecoderConfig.Out)
	if err != nil || want != actual {
		return nil
	}
	return c.behaviorEngine
}

// SetBehaviorEngine installs the early observer before capture starts.
// The caller owns checkpointing and closing the engine and its alert sink.
func (c *Collector) SetBehaviorEngine(engine *behavior.Engine, scope behavior.Scope) {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	c.behaviorEngine, c.behaviorScope = engine, scope
	c.behaviorError = nil
	if engine != nil {
		c.behaviorPackets, c.behaviorQueueDrops = 0, 0
		c.behaviorHealthMu.Lock()
		c.behaviorCaptureHealth = behavior.CaptureHealth{}
		c.behaviorHealthMu.Unlock()
	}
}

func (c *Collector) GetBehaviorEngine() *behavior.Engine {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	return c.behaviorEngine
}

func (c *Collector) GetBehaviorError() error {
	c.dispatchMu.Lock()
	defer c.dispatchMu.Unlock()
	return c.behaviorError
}

func (c *Collector) observeBehavior(packet gopacket.Packet) {
	if c.behaviorEngine == nil || c.behaviorError != nil {
		return
	}
	facts := behavior.PacketFacts(packet, c.behaviorScope)
	if network := packet.NetworkLayer(); network != nil && len(facts) > 0 && c.config != nil && c.config.ResolverConfig.GeolocationDB {
		scope := facts[0].Scope
		for _, pair := range [][2]string{{network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()}, {network.NetworkFlow().Dst().String(), network.NetworkFlow().Src().String()}} {
			geo := resolvers.LookupGeoContext(pair[1])
			if geo.Country != "" || geo.ASN != "" {
				facts = append(facts, behavior.Fact{Scope: scope, Kind: "geo", SrcIP: pair[0], DstIP: pair[1], Value: geo.Country + "|" + geo.ASN, Provenance: strings.Join(geo.Providers, ",")})
			}
		}
	}
	if len(facts) == 0 {
		return
	}
	if err := c.behaviorEngine.Observe(packet.Metadata().CaptureInfo.Timestamp, facts...); err != nil {
		c.behaviorError = err
		c.behaviorEngine.Fail(err)
	}
}
