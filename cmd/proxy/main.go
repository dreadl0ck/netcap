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

package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/io"
)

// a list of all reverse proxies
// used to close all files handles on exit via OS signals.
var proxies []*reverseProxy

// Run parses the subcommand flags and handles the arguments.
func Run() {
	// parse commandline flags
	fs.Usage = printUsage
	err := fs.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	if *flagGenerateConfig {
		io.GenerateConfig(fs, "proxy")
		return
	}

	io.PrintBuildInfo()

	// check if flags have been used to configure a single instance proxy
	if *flagLocal == "" || *flagRemote == "" {
		// parse config file
		var errParseConfig error
		c, errParseConfig = parseConfiguration(*flagProxyConfig)
		if errParseConfig != nil {
			log.Fatal("failed to parse config: ", errParseConfig)
		}
	} else {
		// setup single proxy instance
		c = &config{
			Proxies: map[string]reverseProxyConfig{
				"customproxy": {
					Remote: *flagRemote,
					Local:  *flagLocal,
				},
			},
		}
	}

	// handle OS signals
	handleSignals()

	// print configuration
	fmt.Println("Configuration:")
	c.dump(os.Stdout)

	// configure logger
	configureLogger(*flagDebug, filepath.Join(c.Logdir, logFileName))

	// synchronize the logger on exit
	defer func() {
		errClose := proxyLog.Sync()
		if errClose != nil {
			fmt.Println("failed to sync logger:", errClose)
		}
	}()

	proxyLog.Info("setup complete",
		zap.String("logfile", logFileName),
		zap.String("config", *flagProxyConfig),
	)

	// iterate over proxies from config
	for name, p := range c.Proxies { // copy variables to avoid capturing them
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
				if c.CertFile == "" || c.KeyFile == "" {
					log.Fatal(proxyName, " configured to use TLS for local endpoint, but no missing cert and key in config.")
				}

				// start serving HTTPS
				err = http.ListenAndServeTLS(local, c.CertFile, c.KeyFile, proxy)
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
}
