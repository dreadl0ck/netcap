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

package collect

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/internal/distributed"
	"github.com/dreadl0ck/netcap/internal/netio"
)

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	cmd := &cli.Command{
		Name:  "collect",
		Usage: "collector for audit records from agents",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the collect command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-keypair") {
		fp, err := distributed.GenerateIdentity(c.String("cert"), c.String("key"), "netcap-collector")
		if err != nil {
			return fmt.Errorf("generate keypair: %w", err)
		}

		fmt.Printf("wrote %s and %s\nserver fingerprint (pass to agents as -server-fingerprint):\n%s\n", c.String("cert"), c.String("key"), fp)

		return nil
	}

	netio.PrintBuildInfo()

	if c.String("clients") == "" {
		return errors.New("-clients is required: a file of \"<agent fingerprint> <name>\" lines")
	}

	id, err := distributed.LoadIdentity(c.String("cert"), c.String("key"))
	if err != nil {
		return fmt.Errorf("load identity (generate one with -gen-keypair): %w", err)
	}

	allow, err := distributed.LoadAllowlist(c.String("clients"))
	if err != nil {
		return fmt.Errorf("load %s: %w", c.String("clients"), err)
	}

	sink, err := distributed.NewSink(c.String("out"))
	if err != nil {
		return err
	}

	srv, err := distributed.NewServer(distributed.ServerConfig{
		Identity:    id,
		Allowlist:   allow,
		Sink:        sink,
		MaxFrame:    c.Int("max-frame"),
		MaxConns:    c.Int("max-conns"),
		IdleTimeout: c.Duration("idle-timeout"),
	})
	if err != nil {
		return err
	}

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", c.String("addr"))
	if err != nil {
		return err
	}

	fp, _ := distributed.IdentityFingerprint(id)
	log.Printf("collect: listening on %s, %d allowed clients, writing to %s", ln.Addr(), len(allow), sink.Root())
	log.Printf("collect: server fingerprint %s", fp)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		log.Println("collect: shutting down")
	case err = <-serveErr:
		log.Printf("collect: listener failed: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), c.Duration("shutdown-timeout"))
	defer cancel()

	infos, shutdownErr := srv.Shutdown(shutdownCtx)
	for _, fi := range infos {
		log.Printf("collect: %s: %d records", fi.Path, fi.Records)
	}

	if err != nil && !errors.Is(err, distributed.ErrServerClosed) {
		return errors.Join(err, shutdownErr)
	}

	return shutdownErr
}
