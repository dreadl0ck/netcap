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

package performance

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
)

// Tracker tracks performance metrics for netcap operations
type Tracker struct {
	mu sync.RWMutex

	// Packet processing metrics
	TotalPackets     int64
	TotalBytes       int64
	PacketDecodingNs int64 // Total time spent decoding packets
	PacketCount      int64 // Count of packets decoded

	// TCP reassembly metrics
	ReassemblyNs    int64 // Total time spent in TCP reassembly
	ReassemblyCount int64 // Count of packets reassembled

	// GoPacket decoder metrics (by layer type)
	goPacketDecoders map[string]*DecoderMetrics

	// Custom decoder metrics (by decoder name)
	customDecoders map[string]*DecoderMetrics

	// Stream decoder metrics (by decoder name)
	streamDecoders map[string]*DecoderMetrics

	// Abstract decoder metrics (by decoder name)
	abstractDecoders map[string]*DecoderMetrics

	// Disk I/O metrics (by file type/name)
	diskIO map[string]*DiskIOMetrics

	// DPI metrics
	DPICallsNs int64 // Total time in nanoseconds
	DPICount   int64 // Number of DPI calls

	// Resolver metrics (by resolver type)
	resolvers map[string]*ResolverMetrics

	// Timing
	StartTime time.Time
	EndTime   time.Time
}

// ResolverMetrics tracks metrics for a specific resolver
type ResolverMetrics struct {
	Name     string
	TotalNs  int64 // Total time in nanoseconds
	Count    int64 // Number of lookups
	HitCount int64 // Number of cache hits (if tracked)
}

// DecoderMetrics tracks metrics for a specific decoder
type DecoderMetrics struct {
	Name     string
	TotalNs  int64 // Total time in nanoseconds
	Count    int64 // Number of invocations
	Records  int64 // Number of records produced
	BytesOut int64 // Bytes written for this decoder
}

// DiskIOMetrics tracks disk I/O metrics for a specific file/type
type DiskIOMetrics struct {
	FileName   string
	WriteCount int64 // Number of write operations
	WriteNs    int64 // Total time in nanoseconds for writes
	BytesOut   int64 // Total bytes written
	SyncCount  int64 // Number of sync operations
	SyncNs     int64 // Total time in nanoseconds for syncs
}

// NewTracker creates a new performance tracker
func NewTracker() *Tracker {
	return &Tracker{
		StartTime:        time.Now(),
		goPacketDecoders: make(map[string]*DecoderMetrics),
		customDecoders:   make(map[string]*DecoderMetrics),
		streamDecoders:   make(map[string]*DecoderMetrics),
		abstractDecoders: make(map[string]*DecoderMetrics),
		diskIO:           make(map[string]*DiskIOMetrics),
		resolvers:        make(map[string]*ResolverMetrics),
	}
}

// RecordPacketDecoding records time spent decoding a packet
func (t *Tracker) RecordPacketDecoding(duration time.Duration) {
	atomic.AddInt64(&t.PacketDecodingNs, int64(duration))
	atomic.AddInt64(&t.PacketCount, 1)
}

// RecordReassembly records time spent in TCP reassembly
func (t *Tracker) RecordReassembly(duration time.Duration) {
	atomic.AddInt64(&t.ReassemblyNs, int64(duration))
	atomic.AddInt64(&t.ReassemblyCount, 1)
}

// RecordDPI records time spent in DPI operations
func (t *Tracker) RecordDPI(duration time.Duration) {
	atomic.AddInt64(&t.DPICallsNs, int64(duration))
	atomic.AddInt64(&t.DPICount, 1)
}

// RecordResolver records metrics for a resolver lookup
func (t *Tracker) RecordResolver(name string, duration time.Duration, cacheHit bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.resolvers[name]; !ok {
		t.resolvers[name] = &ResolverMetrics{Name: name}
	}
	m := t.resolvers[name]
	atomic.AddInt64(&m.TotalNs, int64(duration))
	atomic.AddInt64(&m.Count, 1)
	if cacheHit {
		atomic.AddInt64(&m.HitCount, 1)
	}
}

// RecordGoPacketDecoder records metrics for a GoPacket decoder
func (t *Tracker) RecordGoPacketDecoder(layerType string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.goPacketDecoders[layerType]; !ok {
		t.goPacketDecoders[layerType] = &DecoderMetrics{Name: layerType}
	}
	m := t.goPacketDecoders[layerType]
	atomic.AddInt64(&m.TotalNs, int64(duration))
	atomic.AddInt64(&m.Count, 1)
}

// RecordCustomDecoder records metrics for a custom decoder
func (t *Tracker) RecordCustomDecoder(name string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.customDecoders[name]; !ok {
		t.customDecoders[name] = &DecoderMetrics{Name: name}
	}
	m := t.customDecoders[name]
	atomic.AddInt64(&m.TotalNs, int64(duration))
	atomic.AddInt64(&m.Count, 1)
}

// RecordStreamDecoder records metrics for a stream decoder
func (t *Tracker) RecordStreamDecoder(name string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.streamDecoders[name]; !ok {
		t.streamDecoders[name] = &DecoderMetrics{Name: name}
	}
	m := t.streamDecoders[name]
	atomic.AddInt64(&m.TotalNs, int64(duration))
	atomic.AddInt64(&m.Count, 1)
}

// RecordAbstractDecoder records metrics for an abstract decoder
func (t *Tracker) RecordAbstractDecoder(name string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.abstractDecoders[name]; !ok {
		t.abstractDecoders[name] = &DecoderMetrics{Name: name}
	}
	m := t.abstractDecoders[name]
	atomic.AddInt64(&m.TotalNs, int64(duration))
	atomic.AddInt64(&m.Count, 1)
}

// UpdateDecoderRecords updates the record count and bytes for a decoder
func (t *Tracker) UpdateDecoderRecords(decoderType, name string, records, bytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var m *DecoderMetrics
	switch decoderType {
	case "gopacket":
		if _, ok := t.goPacketDecoders[name]; !ok {
			t.goPacketDecoders[name] = &DecoderMetrics{Name: name}
		}
		m = t.goPacketDecoders[name]
	case "custom":
		if _, ok := t.customDecoders[name]; !ok {
			t.customDecoders[name] = &DecoderMetrics{Name: name}
		}
		m = t.customDecoders[name]
	case "stream":
		if _, ok := t.streamDecoders[name]; !ok {
			t.streamDecoders[name] = &DecoderMetrics{Name: name}
		}
		m = t.streamDecoders[name]
	case "abstract":
		if _, ok := t.abstractDecoders[name]; !ok {
			t.abstractDecoders[name] = &DecoderMetrics{Name: name}
		}
		m = t.abstractDecoders[name]
	}

	if m != nil {
		atomic.StoreInt64(&m.Records, records)
		atomic.StoreInt64(&m.BytesOut, bytes)
	}
}

// RecordDiskWrite records a disk write operation
func (t *Tracker) RecordDiskWrite(fileName string, duration time.Duration, bytesWritten int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.diskIO[fileName]; !ok {
		t.diskIO[fileName] = &DiskIOMetrics{FileName: fileName}
	}
	m := t.diskIO[fileName]
	atomic.AddInt64(&m.WriteNs, int64(duration))
	atomic.AddInt64(&m.WriteCount, 1)
	atomic.AddInt64(&m.BytesOut, bytesWritten)
}

// RecordDiskSync records a disk sync operation
func (t *Tracker) RecordDiskSync(fileName string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.diskIO[fileName]; !ok {
		t.diskIO[fileName] = &DiskIOMetrics{FileName: fileName}
	}
	m := t.diskIO[fileName]
	atomic.AddInt64(&m.SyncNs, int64(duration))
	atomic.AddInt64(&m.SyncCount, 1)
}

// SetTotalPacketsAndBytes sets the total packets and bytes processed
func (t *Tracker) SetTotalPacketsAndBytes(packets, bytes int64) {
	atomic.StoreInt64(&t.TotalPackets, packets)
	atomic.StoreInt64(&t.TotalBytes, bytes)
}

// Finalize marks the end time for the tracker
func (t *Tracker) Finalize() {
	t.EndTime = time.Now()
}

// WriteReport writes a performance report to the specified file
func (t *Tracker) WriteReport(filename string) error {
	t.Finalize()

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open performance log: %w", err)
	}
	defer f.Close()

	t.mu.RLock()
	defer t.mu.RUnlock()

	duration := t.EndTime.Sub(t.StartTime)

	// Write header
	fmt.Fprintf(f, "\n")
	fmt.Fprintf(f, "================================================================================\n")
	fmt.Fprintf(f, "NETCAP PERFORMANCE REPORT\n")
	fmt.Fprintf(f, "================================================================================\n")
	fmt.Fprintf(f, "Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "Duration: %v\n", duration)
	fmt.Fprintf(f, "\n")

	// Overall statistics
	fmt.Fprintf(f, "OVERALL STATISTICS\n")
	fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
	fmt.Fprintf(f, "Total Packets:        %d\n", t.TotalPackets)
	fmt.Fprintf(f, "Total Bytes:          %s (%d bytes)\n", humanize.Bytes(uint64(t.TotalBytes)), t.TotalBytes)

	if duration.Seconds() > 0 {
		packetsPerSec := float64(t.TotalPackets) / duration.Seconds()
		mbitsPerSec := (float64(t.TotalBytes) * 8) / (duration.Seconds() * 1000000)
		fmt.Fprintf(f, "Throughput:           %.2f packets/sec, %.2f Mbps\n", packetsPerSec, mbitsPerSec)
	}
	fmt.Fprintf(f, "\n")

	// Packet decoding performance
	if t.PacketCount > 0 {
		avgDecoding := time.Duration(t.PacketDecodingNs / t.PacketCount)
		fmt.Fprintf(f, "PACKET DECODING PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "Packets Decoded:      %d\n", t.PacketCount)
		fmt.Fprintf(f, "Total Time:           %v\n", time.Duration(t.PacketDecodingNs))
		fmt.Fprintf(f, "Average per Packet:   %v\n", avgDecoding)
		if avgDecoding.Nanoseconds() > 0 {
			fmt.Fprintf(f, "Decoding Rate:        %.2f packets/sec\n", 1e9/float64(avgDecoding.Nanoseconds()))
		}
		fmt.Fprintf(f, "\n")
	}

	// TCP reassembly performance
	if t.ReassemblyCount > 0 {
		avgReassembly := time.Duration(t.ReassemblyNs / t.ReassemblyCount)
		fmt.Fprintf(f, "TCP REASSEMBLY PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "Packets Reassembled:  %d\n", t.ReassemblyCount)
		fmt.Fprintf(f, "Total Time:           %v\n", time.Duration(t.ReassemblyNs))
		fmt.Fprintf(f, "Average per Packet:   %v\n", avgReassembly)
		if avgReassembly.Nanoseconds() > 0 {
			fmt.Fprintf(f, "Reassembly Rate:      %.2f packets/sec\n", 1e9/float64(avgReassembly.Nanoseconds()))
		}
		fmt.Fprintf(f, "\n")
	}

	// DPI performance
	if t.DPICount > 0 {
		avgDPI := time.Duration(t.DPICallsNs / t.DPICount)
		fmt.Fprintf(f, "DEEP PACKET INSPECTION (DPI) PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "DPI Calls:            %d\n", t.DPICount)
		fmt.Fprintf(f, "Total Time:           %v\n", time.Duration(t.DPICallsNs))
		fmt.Fprintf(f, "Average per Call:     %v\n", avgDPI)
		if avgDPI.Nanoseconds() > 0 {
			fmt.Fprintf(f, "DPI Call Rate:        %.2f calls/sec\n", 1e9/float64(avgDPI.Nanoseconds()))
		}
		fmt.Fprintf(f, "\n")
	}

	// GoPacket decoders
	if len(t.goPacketDecoders) > 0 {
		fmt.Fprintf(f, "GOPACKET DECODER PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "Decoder", "Count", "Records", "Avg Time", "Total Time")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "-------", "-----", "-------", "--------", "----------")

		// Sort by total time
		decoders := t.getSortedDecoders(t.goPacketDecoders)
		for _, m := range decoders {
			avg := time.Duration(0)
			if m.Count > 0 {
				avg = time.Duration(m.TotalNs / m.Count)
			}
			fmt.Fprintf(f, "%-30s %12d %12d %15v %15v\n",
				m.Name, m.Count, m.Records, avg, time.Duration(m.TotalNs))
		}
		fmt.Fprintf(f, "\n")
	}

	// Custom decoders
	if len(t.customDecoders) > 0 {
		fmt.Fprintf(f, "CUSTOM DECODER PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "Decoder", "Count", "Records", "Avg Time", "Total Time")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "-------", "-----", "-------", "--------", "----------")

		decoders := t.getSortedDecoders(t.customDecoders)
		for _, m := range decoders {
			avg := time.Duration(0)
			if m.Count > 0 {
				avg = time.Duration(m.TotalNs / m.Count)
			}
			fmt.Fprintf(f, "%-30s %12d %12d %15v %15v\n",
				m.Name, m.Count, m.Records, avg, time.Duration(m.TotalNs))
		}
		fmt.Fprintf(f, "\n")
	}

	// Stream decoders
	if len(t.streamDecoders) > 0 {
		fmt.Fprintf(f, "STREAM DECODER PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "Decoder", "Count", "Records", "Avg Time", "Total Time")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "-------", "-----", "-------", "--------", "----------")

		decoders := t.getSortedDecoders(t.streamDecoders)
		for _, m := range decoders {
			avg := time.Duration(0)
			if m.Count > 0 {
				avg = time.Duration(m.TotalNs / m.Count)
			}
			fmt.Fprintf(f, "%-30s %12d %12d %15v %15v\n",
				m.Name, m.Count, m.Records, avg, time.Duration(m.TotalNs))
		}
		fmt.Fprintf(f, "\n")
	}

	// Abstract decoders
	if len(t.abstractDecoders) > 0 {
		fmt.Fprintf(f, "ABSTRACT DECODER PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "Decoder", "Count", "Records", "Avg Time", "Total Time")
		fmt.Fprintf(f, "%-30s %12s %12s %15s %15s\n", "-------", "-----", "-------", "--------", "----------")

		decoders := t.getSortedDecoders(t.abstractDecoders)
		for _, m := range decoders {
			avg := time.Duration(0)
			if m.Count > 0 {
				avg = time.Duration(m.TotalNs / m.Count)
			}
			fmt.Fprintf(f, "%-30s %12d %12d %15v %15v\n",
				m.Name, m.Count, m.Records, avg, time.Duration(m.TotalNs))
		}
		fmt.Fprintf(f, "\n")
	}

	// Resolver performance
	if len(t.resolvers) > 0 {
		fmt.Fprintf(f, "DATABASE/RESOLVER PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "%-30s %12s %12s %12s %15s %15s\n", "Resolver", "Lookups", "Cache Hits", "Hit Rate", "Avg Time", "Total Time")
		fmt.Fprintf(f, "%-30s %12s %12s %12s %15s %15s\n", "--------", "-------", "----------", "--------", "--------", "----------")

		// Sort by total time
		resolverMetrics := t.getSortedResolvers()
		for _, m := range resolverMetrics {
			avg := time.Duration(0)
			if m.Count > 0 {
				avg = time.Duration(m.TotalNs / m.Count)
			}
			hitRate := "N/A"
			if m.Count > 0 {
				hitRate = fmt.Sprintf("%.1f%%", float64(m.HitCount)*100.0/float64(m.Count))
			}
			fmt.Fprintf(f, "%-30s %12d %12d %12s %15v %15v\n",
				m.Name, m.Count, m.HitCount, hitRate, avg, time.Duration(m.TotalNs))
		}
		fmt.Fprintf(f, "\n")
	}

	// Disk I/O performance
	if len(t.diskIO) > 0 {
		fmt.Fprintf(f, "DISK I/O PERFORMANCE\n")
		fmt.Fprintf(f, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(f, "%-40s %10s %15s %15s\n", "File", "Writes", "Bytes", "Total Time")
		fmt.Fprintf(f, "%-40s %10s %15s %15s\n", "----", "------", "-----", "----------")

		// Sort by bytes written
		diskMetrics := t.getSortedDiskIO()
		var totalWrites, totalBytes, totalTime int64
		for _, m := range diskMetrics {
			fmt.Fprintf(f, "%-40s %10d %15s %15v\n",
				truncate(m.FileName, 40), m.WriteCount,
				humanize.Bytes(uint64(m.BytesOut)), time.Duration(m.WriteNs))
			totalWrites += m.WriteCount
			totalBytes += m.BytesOut
			totalTime += m.WriteNs
		}
		fmt.Fprintf(f, "%-40s %10s %15s %15s\n", "----", "------", "-----", "----------")
		fmt.Fprintf(f, "%-40s %10d %15s %15v\n", "TOTAL", totalWrites, humanize.Bytes(uint64(totalBytes)), time.Duration(totalTime))

		if totalBytes > 0 && totalTime > 0 {
			mbps := (float64(totalBytes) * 8) / (float64(totalTime) / 1e9) / 1e6
			fmt.Fprintf(f, "\nDisk I/O Throughput:  %.2f MB/s\n", mbps)
		}
		fmt.Fprintf(f, "\n")
	}

	fmt.Fprintf(f, "================================================================================\n")
	fmt.Fprintf(f, "\n")

	return nil
}

// getSortedDecoders returns decoder metrics sorted by total time (descending)
func (t *Tracker) getSortedDecoders(decoders map[string]*DecoderMetrics) []*DecoderMetrics {
	sorted := make([]*DecoderMetrics, 0, len(decoders))
	for _, m := range decoders {
		sorted = append(sorted, m)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TotalNs > sorted[j].TotalNs
	})
	return sorted
}

// getSortedDiskIO returns disk I/O metrics sorted by bytes written (descending)
func (t *Tracker) getSortedDiskIO() []*DiskIOMetrics {
	sorted := make([]*DiskIOMetrics, 0, len(t.diskIO))
	for _, m := range t.diskIO {
		sorted = append(sorted, m)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].BytesOut > sorted[j].BytesOut
	})
	return sorted
}

// getSortedResolvers returns resolver metrics sorted by total time (descending)
func (t *Tracker) getSortedResolvers() []*ResolverMetrics {
	sorted := make([]*ResolverMetrics, 0, len(t.resolvers))
	for _, m := range t.resolvers {
		sorted = append(sorted, m)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TotalNs > sorted[j].TotalNs
	})
	return sorted
}

// truncate truncates a string to the specified length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
