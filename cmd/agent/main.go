/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap"
	behaviorcommand "github.com/dreadl0ck/netcap/internal/behavior/command"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/distributed"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
)

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	cmd := &cli.Command{
		Name:  "agent",
		Usage: "agent for distributed capture",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the agent command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) (runErr error) {
	if c.Bool("gen-keypair") {
		fp, err := distributed.GenerateIdentity(c.String("cert"), c.String("key"), "netcap-agent")
		if err != nil {
			return fmt.Errorf("generate keypair: %w", err)
		}

		fmt.Printf("wrote %s and %s\nagent fingerprint (add to the collector's -clients file):\n%s <name>\n", c.String("cert"), c.String("key"), fp)

		return nil
	}

	if c.Bool("decoders") {
		packet.ShowDecoders(true)
		return nil
	}

	if c.Bool("interfaces") {
		utils.ListAllNetworkInterfaces()
		return nil
	}

	netio.PrintBuildInfo()

	if c.String("server-fingerprint") == "" {
		return errors.New("-server-fingerprint is required: the collector prints it on startup and on -gen-keypair")
	}

	id, err := distributed.LoadIdentity(c.String("cert"), c.String("key"))
	if err != nil {
		return fmt.Errorf("load identity (generate one with -gen-keypair): %w", err)
	}

	client, err := distributed.NewClient(distributed.ClientConfig{
		Addr:              c.String("addr"),
		Identity:          id,
		ServerFingerprint: c.String("server-fingerprint"),
		Hello: types.AgentHello{
			Source:           c.String("iface"),
			Version:          netcap.Version,
			ContainsPayloads: c.Bool("payload"),
		},
		MaxPending: c.Int("max-pending"),
	})
	if err != nil {
		return err
	}

	// Start from the decoder defaults: a bare literal leaves fields such as
	// NumStreamWorkers at zero, which panics the connection decoder on teardown.
	dc := config.DefaultConfig.Clone()
	dc.Buffer = false
	dc.Compression = false
	dc.CSV = false
	dc.Chan = true
	dc.ChanSize = c.Int("chan-size")
	dc.IncludeDecoders = c.String("include")
	dc.ExcludeDecoders = c.String("exclude")
	dc.Out = ""
	dc.Source = c.String("iface")
	dc.IncludePayloads = c.Bool("payload")
	dc.AddContext = c.Bool("context")
	dc.MemBufferSize = c.Int("membuf-size")
	dc.FlushEvery = c.Int("flushevery")
	dc.DefragIPv4 = c.Bool("ip4defrag")
	dc.Checksum = c.Bool("checksum")
	dc.NoOptCheck = c.Bool("nooptcheck")
	dc.IgnoreFSMerr = c.Bool("ignorefsmerr")
	dc.AllowMissingInit = c.Bool("allowmissinginit")
	dc.Debug = c.Bool("debug")
	dc.HexDump = c.Bool("hexdump")
	dc.WaitForConnections = c.Bool("wait-conns")
	dc.WriteIncomplete = c.Bool("writeincomplete")
	dc.MemProfile = c.String("memprofile")
	dc.ConnFlushInterval = c.Int("conn-flush-interval")
	dc.ConnTimeOut = c.Duration("conn-timeout")
	dc.FlowFlushInterval = c.Int("flow-flush-interval")
	dc.FlowTimeOut = c.Duration("flow-timeout")
	dc.CloseInactiveTimeOut = c.Duration("close-inactive-timeout")
	dc.ClosePendingTimeOut = c.Duration("close-pending-timeout")
	dc.FileStorage = c.String("fileStorage")
	dc.CalculateEntropy = c.Bool("entropy")

	// init collector
	coll := collector.New(collector.Config{
		Workers:             c.Int("workers"),
		PacketBufferSize:    c.Int("pbuf"),
		WriteUnknownPackets: false,
		Promisc:             c.Bool("promisc"),
		SnapLen:             c.Int("snaplen"),
		LogErrors:           c.Bool("log-errors"),
		// Without reassembly no stream decoder (HTTP, SMTP, ...) produces records.
		ReassembleConnections: c.Bool("reassemble-connections"),
		DecoderConfig:         dc,
		// The agent owns SIGINT/SIGTERM: the capture collector's handler would
		// os.Exit before queued batches are delivered.
		NoSignalHandling: true,
		ResolverConfig: resolvers.Config{
			ReverseDNS:    c.Bool("reverse-dns"),
			LocalDNS:      c.Bool("local-dns"),
			MACDB:         c.Bool("macDB"),
			JA4DB:         c.Bool("ja4DB"),
			ServiceDB:     c.Bool("serviceDB"),
			GeolocationDB: c.Bool("geoDB"),
			GeoProviders:  c.String("geoProviders"),
		},
		DPI:           c.Bool("dpi"),
		DPIModules:    c.String("dpi-modules"),
		BaseLayer:     utils.GetBaseLayer(c.String("base")),
		DecodeOptions: utils.GetDecodeOptions(c.String("opts")),
	})

	behaviorOptions := behaviorcommand.ReadOptions(c)
	if behaviorOptions.Enabled {
		output := filepath.Dir(c.String("behavior-baseline"))
		if c.String("behavior-baseline") == "" {
			dir, err := os.UserConfigDir()
			if err != nil {
				return err
			}
			output = filepath.Join(dir, "netcap", "behavior", filepath.Base(c.String("iface")))
		}
		if !c.IsSet("behavior-sensor") {
			behaviorOptions.Sensor, _ = distributed.IdentityFingerprint(id)
		}
		behaviorOptions.OnAlert = func(alert *types.Alert) {
			var data bytes.Buffer
			if err := delimited.NewWriter(&data).PutProto(alert); err != nil {
				log.Printf("agent: behavioral alert encoding failed: %v", err)
				return
			}
			if data.Len() > distributed.MaxRecordSize {
				log.Printf("agent: behavioral alert retained locally but exceeds remote record limit")
				return
			}
			if err := client.Enqueue(&types.Batch{MessageType: types.Type_NC_Alert, TotalSize: int32(data.Len()), Data: data.Bytes()}); err != nil {
				log.Printf("agent: behavioral alert retained locally, remote delivery unavailable: %v", err)
			}
		}
		stopBehavior, err := behaviorcommand.StartOptions(behaviorOptions, coll, output, c.String("iface"), true)
		if err != nil {
			return fmt.Errorf("start agent behavioral monitoring: %w", err)
		}
		defer func() { runErr = errors.Join(runErr, stopBehavior()) }()
	}

	// initialize batching
	chans, handle, err := coll.InitBatching(c.String("bpf"), c.String("iface"))
	if err != nil {
		_, _ = client.Close(context.Background())

		return err
	}

	fp, _ := distributed.IdentityFingerprint(id)
	log.Printf("agent: %d decoder channels, sending to %s as %s", len(chans), c.String("addr"), fp)

	var (
		wg        sync.WaitGroup
		oversized atomic.Int64
	)

	for _, bi := range chans {
		wg.Add(1)

		go func() {
			defer wg.Done()

			distributed.RunBatcher(bi.Chan, distributed.BatcherConfig{
				Type:             bi.Type,
				MaxBytes:         c.Int("max"),
				FlushInterval:    c.Duration("flush-interval"),
				ContainsPayloads: c.Bool("payload"),
				Emit: func(b *types.Batch) {
					if errEnq := client.Enqueue(b); errEnq != nil {
						log.Printf("agent: %s batch lost: %v", bi.Type, errEnq)
					}
				},
				OnOversize: func(size int) {
					oversized.Add(1)
					log.Printf("agent: dropped %s record of %d bytes, over the %d byte limit", bi.Type, size, distributed.MaxRecordSize)
				},
			})
		}()
	}

	batchersDone := make(chan struct{})
	go func() { wg.Wait(); close(batchersDone) }()

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Println("agent: stopping capture")
	case <-batchersDone:
		log.Println("agent: capture ended")
	}

	// Closing the handle ends capture; teardown destroys the decoders, which
	// closes their channels, and each batcher sends what it holds.
	handle.Close()
	<-batchersDone

	shutdownCtx, cancel := context.WithTimeout(context.Background(), c.Duration("shutdown-timeout"))
	defer cancel()

	st, err := client.Close(shutdownCtx)
	log.Printf("agent: %d batches delivered, %d rejected, %d dropped for backlog, %d undelivered, %d oversized records dropped",
		st.Acked, st.Rejected, st.Dropped, st.Pending, oversized.Load())

	if err != nil {
		return fmt.Errorf("%d batches undelivered: %w", st.Pending, err)
	}

	return nil
}
