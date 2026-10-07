package flow

import (
	"context"
	"sort"
)

type Distribution struct {
	Count  int   `json:"count"`
	Min    int64 `json:"min,string"`
	Median int64 `json:"median,string"`
	P95    int64 `json:"p95,string"`
	Max    int64 `json:"max,string"`
}
type Statistics struct {
	Bytes                Distribution     `json:"bytes"`
	Packets              Distribution     `json:"packets"`
	DurationNs           Distribution     `json:"durationNs"`
	AverageBitsPerSecond RateDistribution `json:"averageBitsPerSecond"`
}

// Zero-duration records have no defined rate and are counted separately.
type RateDistribution struct {
	Count     int     `json:"count"`
	Undefined int     `json:"undefined"`
	Min       float64 `json:"min"`
	Median    float64 `json:"median"`
	P95       float64 `json:"p95"`
	Max       float64 `json:"max"`
}
type Bucket struct {
	StartNs                int64   `json:"startNs,string"`
	EndNs                  int64   `json:"endNs,string"`
	EstimatedBytes         float64 `json:"estimatedBytes"`
	EstimatedClientBytes   float64 `json:"estimatedClientBytes"`
	EstimatedServerBytes   float64 `json:"estimatedServerBytes"`
	EstimatedBitsPerSecond float64 `json:"estimatedBitsPerSecond"`
	DirectionalComplete    bool    `json:"directionalComplete"`
}
type seriesSample struct{ start, end, bytes, packets, client, server int64 }

func matchesWindow(start, end int64, q Query) bool {
	switch q.WindowMode {
	case "contained":
		return start >= q.StartNs && end <= q.EndNs
	case "start":
		return start >= q.StartNs && start <= q.EndNs
	case "end":
		return end >= q.StartNs && end <= q.EndNs
	default:
		return start <= q.EndNs && end >= q.StartNs
	}
}

func distribution(values []int64) Distribution {
	if len(values) == 0 {
		return Distribution{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return Distribution{Count: len(values), Min: values[0], Median: values[(len(values)-1)/2], P95: values[(95*len(values)+99)/100-1], Max: values[len(values)-1]}
}

func sampleStatistics(samples []seriesSample) Statistics {
	bytes, packets, durations := make([]int64, len(samples)), make([]int64, len(samples)), make([]int64, len(samples))
	var rates []float64
	for i, s := range samples {
		bytes[i], packets[i], durations[i] = s.bytes, s.packets, s.end-s.start
		if s.end > s.start {
			rates = append(rates, float64(s.bytes)*8e9/float64(s.end-s.start))
		}
	}
	sort.Float64s(rates)
	r := RateDistribution{Count: len(rates), Undefined: len(samples) - len(rates)}
	if len(rates) > 0 {
		r.Min, r.Median, r.P95, r.Max = rates[0], rates[(len(rates)-1)/2], rates[(95*len(rates)+99)/100-1], rates[len(rates)-1]
	}
	return Statistics{Bytes: distribution(bytes), Packets: distribution(packets), DurationNs: distribution(durations), AverageBitsPerSecond: r}
}

func sampleSeries(ctx context.Context, samples []seriesSample, q Query) ([]Bucket, error) {
	span := q.EndNs - q.StartNs
	count := int(span / q.BucketNs)
	if span%q.BucketNs != 0 {
		count++
	}
	buckets := make([]Bucket, count)
	for i := range buckets {
		start := q.StartNs + int64(i)*q.BucketNs
		remaining := q.EndNs - start
		end := q.EndNs
		if remaining > q.BucketNs {
			end = start + q.BucketNs
		}
		buckets[i].StartNs, buckets[i].EndNs = start, end
		buckets[i].DirectionalComplete = true
	}
	for _, s := range samples {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		known := s.client >= 0 && s.server >= 0 && s.client <= s.bytes && s.server == s.bytes-s.client
		start, end := max(s.start, q.StartNs), min(s.end, q.EndNs)
		if end < start {
			continue
		}
		if s.start == s.end {
			index := min(int((start-q.StartNs)/q.BucketNs), count-1)
			if index >= 0 {
				bucket := &buckets[index]
				bucket.EstimatedBytes += float64(s.bytes)
				bucket.DirectionalComplete = bucket.DirectionalComplete && known
				if known {
					bucket.EstimatedClientBytes += float64(s.client)
					bucket.EstimatedServerBytes += float64(s.server)
				}
			}
			continue
		}
		first := int((start - q.StartNs) / q.BucketNs)
		last := min(int((end-q.StartNs)/q.BucketNs), count-1)
		for i := first; i <= last; i++ {
			bucket := &buckets[i]
			overlap := min(end, bucket.EndNs) - max(start, bucket.StartNs)
			if overlap <= 0 {
				continue
			}
			weight := float64(overlap) / float64(s.end-s.start)
			bucket.EstimatedBytes += float64(s.bytes) * weight
			bucket.DirectionalComplete = bucket.DirectionalComplete && known
			if known {
				bucket.EstimatedClientBytes += float64(s.client) * weight
				bucket.EstimatedServerBytes += float64(s.server) * weight
			}
		}
	}
	for i := range buckets {
		buckets[i].EstimatedBitsPerSecond = buckets[i].EstimatedBytes * 8e9 / float64(buckets[i].EndNs-buckets[i].StartNs)
	}
	return buckets, nil
}
