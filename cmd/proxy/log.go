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
	"log"

	"go.uber.org/zap"
)

// logFileName holds name of the logfile.
const logFileName = "net.proxy.log"

// logging instance.
var proxyLog = zap.NewNop()

// configureLogger configures the logging instance.
func configureLogger(debug bool, outputPath string) {
	var (
		zc  zap.Config
		err error
	)

	if debug {
		// use dev config
		zc = zap.NewDevelopmentConfig()
	} else {
		// use prod config
		zc = zap.NewProductionConfig()
	}

	// append outputPath
	zc.OutputPaths = append(zc.OutputPaths, outputPath)

	proxyLog, err = zc.Build()
	if err != nil {
		log.Fatalf("failed to initialize zap logger: %v", err)
	}
}
