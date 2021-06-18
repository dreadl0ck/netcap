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

package collector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/decoder/db"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/resolvers"
)

// initLogging can be used to open the logfile before calling Init()
// this is used to be able to dump the collector configuration into the netcap.log in quiet mode
// following calls to Init() will not open the filehandle again.
func (c *Collector) initLogging() error {

	// prevent reopen
	//if c.netcapLogFile != nil {
	//	return nil
	//}

	if c.config.DecoderConfig.Out != "" {
		if stat, err := os.Stat(c.config.DecoderConfig.Out); err != nil {
			err = os.MkdirAll(c.config.DecoderConfig.Out, defaults.DirectoryPermission)
			if err != nil {
				fmt.Println(err)
			}

			_, err = os.Stat(c.config.DecoderConfig.Out)
			if err != nil {
				return err
			}
		} else if !stat.IsDir() {
			return errInvalidOutputDirectory
		}
	}

	// setup summary logger for netcap execution
	lNetcap, netcapLogFile, err := logger.InitDebugLogger(c.config.DecoderConfig.Out, "netcap", true) // pass true because we always want to create this file
	if err != nil {
		return err
	}

	c.netcapLog = lNetcap
	c.netcapLogFile = netcapLogFile

	// setup logger for collector
	lCollector, collectorLogFile, err := logger.InitZapLogger(c.config.DecoderConfig.Out, "collector", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	c.log = lCollector

	// setup logger for resolvers
	lResolvers, resolversLogFile, err := logger.InitZapLogger(c.config.DecoderConfig.Out, "resolvers", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	resolvers.SetLogger(lResolvers)

	// setup logger for io pkg
	lIO, ioLogFile, err := logger.InitZapLogger(c.config.DecoderConfig.Out, "io", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	netio.SetLogger(lIO)

	// setup general logger for decoder pkg
	lDecoder, decoderLogFile, err := logger.InitZapLogger(c.config.DecoderConfig.Out, "decoder", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	packet.SetDecoderLogger(lDecoder)

	lDB, dbLogFile, err := logger.InitZapLogger(c.config.DecoderConfig.Out, "db", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	db.SetLogger(lDB)

	// setup logger for reassembly pkg
	lReassembly, reassemblyLogFile, err := logger.InitZapLogger(c.config.DecoderConfig.Out, "reassembly", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	streamutils.SetLogger(lReassembly)
	tcp.SetLogger(lReassembly)

	// store pointers to zap loggers, in order to sync them on exit
	c.zapLoggers = append(c.zapLoggers,
		c.log,
		lResolvers,
		lIO,
		lDecoder,
		lReassembly,
		lDB,
	)

	// store file handles for closing on exit
	c.logFileHandles = append(c.logFileHandles,
		netcapLogFile,
		collectorLogFile,
		resolversLogFile,
		ioLogFile,
		decoderLogFile,
		reassemblyLogFile,
		dbLogFile,
	)

	// create errors.log file
	c.mu.Lock()
	c.errorLogFile, err = os.Create(filepath.Join(c.config.DecoderConfig.Out, "errors.log"))
	c.mu.Unlock()

	return nil
}
