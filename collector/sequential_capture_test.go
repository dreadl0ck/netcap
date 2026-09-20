package collector

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
)

// TestSequentialCaptures runs several captures in one process, the way the
// capture binary and the service mode web UI process a queue of files. Each run
// must reassemble every conversation on its own, without inheriting streams or
// assemblers from the previous run.
func TestSequentialCaptures(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sequential.pcap")
	workerReplayPCAP(t, input, 1)

	// Vary the worker count so each run rebuilds a different number of pools.
	for run, workers := range []int{4, 1, 8} {
		out := filepath.Join(dir, fmt.Sprintf("run-%d", run))
		c := New(Config{
			Workers: workers, PacketBufferSize: 8, ReassembleConnections: true,
			NoSignalHandling: true, NoPrompt: true,
			BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default,
			DecoderConfig: &config.Config{
				Out: out, Quiet: true,
				IncludeDecoders: "HTTP", Proto: true, Buffer: true, MemBufferSize: 4096,
				SaveConns: true, WaitForConnections: true, NoOptCheck: true,
				ClosePendingTimeOut: 5 * time.Second, CloseInactiveTimeOut: time.Minute,
				StreamBufferSize: 8, StreamDecoderBufSize: 8, NumStreamWorkers: 4, BannerSize: 256,
			},
		})
		if err := c.CollectPcap(input); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if got := c.GetNumPackets(); got != int64(workerReplayPackets) {
			t.Fatalf("run %d: processed packets = %d, want %d", run, got, workerReplayPackets)
		}

		// The capture binary repeats this between files; it must stay a no-op
		// once cleanup has already released the stopped assemblers.
		c.FlushAssemblers()
		tcp.CloseStreamReaderChannelsAndWaitQuiet()

		workerReplayVerify(t, out, 1)
	}
}
