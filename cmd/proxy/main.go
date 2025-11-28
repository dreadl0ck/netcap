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

package proxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/io"
)

// a list of all reverse proxies
// used to close all files handles on exit via OS signals.
var proxies []*reverseProxy

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "proxy",
		Usage: "HTTP proxy for traffic inspection",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the proxy command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-config") {
		// TODO: Update GenerateConfig to work with urfave/cli
		fmt.Println("gen-config not yet implemented with urfave/cli")
		return nil
	}

	io.PrintBuildInfo()

	// Set global variables for helper functions
	flagDebug = c.Bool("debug")
	flagTrace = c.Bool("trace")
	flagDump = c.Bool("dump")
	flagDumpFormatted = c.Bool("format")
	flagDialTimeout = c.Int("dialTimeout")
	flagMaxIdleConns = c.Int("maxIdle")
	flagIdleConnTimeout = c.Int("idleConnTimeout")
	flagTLSHandshakeTimeout = c.Int("tlsTimeout")
	flagSkipTLSVerify = c.Bool("skipTlsVerify")
	flagMemBufferSize = c.Int("membuf-size")

	var proxyConf *config
	var err error

	// check if flags have been used to configure a single instance proxy
	flagLocal := c.String("local")
	flagRemote := c.String("remote")
	flagProxyConfig := c.String("proxy-config")

	if flagLocal == "" || flagRemote == "" {
		// parse config file
		proxyConf, err = parseConfiguration(flagProxyConfig)
		if err != nil {
			log.Fatal("failed to parse config: ", err)
		}
	} else {
		// setup single proxy instance
		proxyConf = &config{
			Proxies: map[string]reverseProxyConfig{
				"customproxy": {
					Remote: flagRemote,
					Local:  flagLocal,
				},
			},
		}
	}

	// handle OS signals
	handleSignals()

	// print configuration
	fmt.Println("Configuration:")
	proxyConf.dump(os.Stdout)

	// configure logger
	configureLogger(c.Bool("debug"), filepath.Join(proxyConf.Logdir, logFileName))

	// synchronize the logger on exit
	defer func() {
		errClose := proxyLog.Sync()
		if errClose != nil {
			fmt.Println("failed to sync logger:", errClose)
		}
	}()

	proxyLog.Info("setup complete",
		zap.String("logfile", logFileName),
		zap.String("config", flagProxyConfig),
	)

	// iterate over proxies from config
	for name, p := range proxyConf.Proxies { // copy variables to avoid capturing them
		// when dispatching a goroutine
		var (
			proxyName = name
			local     = p.Local
			remote    = p.Remote
			tls       = p.TLS
		)

		// spawn a goroutine for each proxy
		go func() {
			proxyLog.Info("initializing proxy",
				zap.String("local", local),
				zap.String("remote", remote),
				zap.String("proxyName", proxyName),
			)

			// parse remote URL
			targetURL, errURL := url.Parse(remote)
			if errURL != nil {
				panic(errURL)
			}

			// instantiate proxy
			proxy := newReverseProxy(proxyName, targetURL)
			proxies = append(proxies, proxy)

			if tls { // check if key and cert file have been specified
				if proxyConf.CertFile == "" || proxyConf.KeyFile == "" {
					log.Fatal(proxyName, " configured to use TLS for local endpoint, but no missing cert and key in config.")
				}

				// start serving HTTPS
				err = http.ListenAndServeTLS(local, proxyConf.CertFile, proxyConf.KeyFile, proxy)
				if err != nil {
					log.Fatal(proxyName, " failed. error: ", err)
				}
			} else {
				// start serving HTTP
				err = http.ListenAndServe(local, proxy)
				if err != nil {
					log.Fatal(proxyName, " failed. error: ", err)
				}
			}
		}()
	}

	// wait until the end of time
	<-make(chan bool)

	return nil
}
