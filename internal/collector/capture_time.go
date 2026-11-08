package collector

import "time"

// dispatchMu orders the capture watermark before the packet advancing it.
// EOF is finalized by FlushAll; replay speed and wall-clock pauses are irrelevant.
func (c *Collector) advanceCaptureTime(ref time.Time) time.Time {
	if c.captureKind != "file" || !c.config.DecoderConfig.CaptureTimeIdleExpiry {
		return ref
	}
	if ref.Before(c.offlineWatermark) {
		c.offlineLatePackets++
	}
	if ref.After(c.offlineWatermark) {
		c.offlineWatermark = ref
	}
	if c.offlineMaintenance.IsZero() {
		c.offlineMaintenance = c.offlineWatermark
		return c.offlineWatermark
	}
	if c.offlineWatermark.Sub(c.offlineMaintenance) >= time.Second {
		for _, worker := range c.workers {
			worker <- &workerControl{ref: c.offlineWatermark, idle: true}
		}
		c.offlineMaintenance = c.offlineWatermark
	}
	return c.offlineWatermark
}
