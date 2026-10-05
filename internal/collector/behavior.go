package collector

import (
	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/gopacket/gopacket"
	"path/filepath"
)

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
	if len(facts) == 0 {
		return
	}
	if err := c.behaviorEngine.Observe(packet.Metadata().CaptureInfo.Timestamp, facts...); err != nil {
		c.behaviorError = err
		c.behaviorEngine.Fail(err)
	}
}
