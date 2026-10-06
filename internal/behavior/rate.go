package behavior

import (
	"fmt"
	"math"
)

func validRateModel(model RateModel) bool {
	for _, value := range []float64{model.PacketsMean, model.PacketsM2, model.BytesMean, model.BytesM2} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return false
		}
	}
	return true
}

func updateRate(model *RateModel, packets, bytes float64) {
	model.Windows++
	count := float64(model.Windows)
	delta := packets - model.PacketsMean
	model.PacketsMean += delta / count
	model.PacketsM2 += delta * (packets - model.PacketsMean)
	delta = bytes - model.BytesMean
	model.BytesMean += delta / count
	model.BytesM2 += delta * (bytes - model.BytesMean)
}

func addIdleWindows(model *RateModel, zeros uint64) {
	if zeros == 0 {
		return
	}
	n, m := float64(model.Windows), float64(zeros)
	if n == 0 {
		model.Windows = zeros
		return
	}
	model.PacketsM2 += model.PacketsMean * model.PacketsMean * n * m / (n + m)
	model.BytesM2 += model.BytesMean * model.BytesMean * n * m / (n + m)
	model.PacketsMean *= n / (n + m)
	model.BytesMean *= n / (n + m)
	model.Windows += zeros
}

func (e *Engine) observeRate(ns int64, id string, fact Fact) error {
	window := e.state.Policy.WindowNS
	start := ns / window * window
	rate, exists := e.state.Rates[id]
	if !exists {
		if len(e.state.Rates) >= e.config.MaxFacts {
			e.state.WindowOverflow++
			return nil
		}
		stable := fact
		stable.Bytes = 0
		rate = RateStats{Fact: stable, Start: start}
	}
	if start < rate.Start {
		return nil
	}
	if start > rate.Start {
		if e.state.Mode == Learning {
			updateRate(&rate.Model, float64(rate.Packets), float64(rate.Bytes))
			addIdleWindows(&rate.Model, uint64((start-rate.Start)/window-1))
		}
		rate.Start, rate.Packets, rate.Bytes = start, 0, 0
	}
	rate.Packets++
	rate.Bytes += fact.Bytes
	e.state.Rates[id] = rate
	if e.state.Mode != Monitoring || e.approvedSource(fact.SrcIP, ns) {
		return nil
	}
	if _, suppressed := e.state.Suppressed[id]; suppressed {
		return nil
	}
	model, known := e.state.ApprovedRates[id]
	if !known || model.Windows < e.state.Policy.RateWindows {
		return nil
	}
	packetLimit := rateLimit(model.PacketsMean, model.PacketsM2, model.Windows, e.state.Policy.RateMultiplier, 100)
	byteLimit := rateLimit(model.BytesMean, model.BytesM2, model.Windows, e.state.Policy.RateMultiplier, 1<<20)
	if float64(rate.Packets) > packetLimit {
		if err := e.emitCorrelation(ns, "baseline.packet-rate", id, fact, fmt.Sprintf("packets per window ≤ %.0f; learned across %d windows", packetLimit, model.Windows), int(rate.Packets), nil, ""); err != nil {
			return err
		}
	}
	if float64(rate.Bytes) > byteLimit {
		return e.emitCorrelation(ns, "baseline.byte-rate", id, fact, fmt.Sprintf("bytes per window ≤ %.0f; learned across %d windows", byteLimit, model.Windows), int(rate.Bytes), nil, "")
	}
	return nil
}

func rateLimit(mean, m2 float64, windows uint64, multiplier, floor float64) float64 {
	deviation := 0.0
	if windows > 1 {
		deviation = math.Sqrt(m2 / float64(windows-1))
	}
	return math.Max(floor, mean*multiplier+6*deviation)
}
