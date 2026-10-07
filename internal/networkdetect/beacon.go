package networkdetect

import (
	"fmt"
	"math"
)

// SyntheticOnlyCase reports qualification cases without a captured FlightSim
// execution: the benign controls and periodic beacons, which FlightSim at the
// pinned revision does not generate.
func SyntheticOnlyCase(name string) bool {
	return name == "benign" || name == "beacon"
}

// maxBeaconTimes bounds the connection starts kept per source and service.
const maxBeaconTimes = 64

type beacon struct {
	times []int64
	seq   uint32
}

type addFunc func(detector, class, severity, mitre string, count, threshold uint64, samples []string, first int64, indicator *Indicator, limitations ...string)

// BeaconStats summarizes the intervals between consecutive connection starts.
// Jitter is the coefficient of variation (standard deviation / mean).
func BeaconStats(times []int64) (mean, jitter float64) {
	if len(times) < 2 {
		return 0, 0
	}
	n := float64(len(times) - 1)
	for i := 1; i < len(times); i++ {
		mean += float64(times[i] - times[i-1])
	}
	mean /= n
	if mean <= 0 {
		return mean, 0
	}
	var variance float64
	for i := 1; i < len(times); i++ {
		d := float64(times[i]-times[i-1]) - mean
		variance += d * d
	}
	return mean, math.Sqrt(variance/n) / mean
}

// observeBeacon times TCP connection starts per source and destination
// service and reports the latest BeaconSamples when their intervals are
// regular.
func (e *Engine) observeBeacon(ev Event, add addFunc) {
	c := e.config
	if c.BeaconSamples == 0 {
		return
	}
	key := e.key(ev, fmt.Sprintf("beacon|%s|%d", ev.DstIP, ev.DstPort))
	b := e.beacons[key]
	if b == nil {
		if len(e.beacons) >= c.MaxKeys {
			e.stats.Overflow++
			return
		}
		b = &beacon{}
		e.beacons[key] = b
	} else if ev.Seq == b.seq {
		// A retransmitted SYN is the same connection attempt.
		return
	}
	b.seq = ev.Seq

	drop := 0
	for drop < len(b.times) && ev.At-b.times[drop] > c.BeaconWindowNS {
		drop++
	}
	if len(b.times)-drop >= maxBeaconTimes {
		drop = len(b.times) - maxBeaconTimes + 1
	}
	b.times = append(b.times[drop:], ev.At)

	if len(b.times) < c.BeaconSamples {
		return
	}
	recent := b.times[len(b.times)-c.BeaconSamples:]
	mean, jitter := BeaconStats(recent)
	if mean < float64(c.BeaconMinIntervalNS) || jitter > c.BeaconJitter {
		return
	}
	samples := []string{
		fmt.Sprintf("service=%s:%d", ev.DstIP, ev.DstPort),
		fmt.Sprintf("meanInterval=%.3fs", mean/1e9),
		fmt.Sprintf("jitter=%.3f", jitter),
	}
	add("c2.beacon", "behavioral-suspicion", "low", "T1071", uint64(len(recent)), uint64(c.BeaconSamples), samples, recent[0], nil,
		"Updates, monitoring, telemetry and keep-alive polling are also periodic; payload and intent are not inferred",
		"Only TCP connection starts are timed; UDP and requests inside one long-lived connection are not")
}

func (e *Engine) expireBeacons(at int64) {
	for k, b := range e.beacons {
		if len(b.times) == 0 || at-b.times[len(b.times)-1] > e.config.BeaconWindowNS {
			delete(e.beacons, k)
		}
	}
}
