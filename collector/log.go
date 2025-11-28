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
	"github.com/dreadl0ck/netcap/internal/logger"
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

	// setup logger for collector with atomic level
	lCollector, collectorLogFile, collectorLevel, err := logger.InitZapLoggerWithAtomicLevel(c.config.DecoderConfig.Out, "collector", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	c.log = lCollector

	// setup logger for resolvers with atomic level
	lResolvers, resolversLogFile, resolversLevel, err := logger.InitZapLoggerWithAtomicLevel(c.config.DecoderConfig.Out, "resolvers", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	resolvers.SetLogger(lResolvers)

	// setup logger for io pkg with atomic level
	lIO, ioLogFile, ioLevel, err := logger.InitZapLoggerWithAtomicLevel(c.config.DecoderConfig.Out, "io", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	netio.SetLogger(lIO)

	// setup general logger for decoder pkg with atomic level
	lDecoder, decoderLogFile, decoderLevel, err := logger.InitZapLoggerWithAtomicLevel(c.config.DecoderConfig.Out, "decoder", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	packet.SetDecoderLogger(lDecoder)

	lDB, dbLogFile, dbLevel, err := logger.InitZapLoggerWithAtomicLevel(c.config.DecoderConfig.Out, "db", c.config.DecoderConfig.Debug)
	if err != nil {
		return err
	}

	db.SetLogger(lDB)

	// setup logger for reassembly pkg with atomic level
	lReassembly, reassemblyLogFile, reassemblyLevel, err := logger.InitZapLoggerWithAtomicLevel(c.config.DecoderConfig.Out, "reassembly", c.config.DecoderConfig.Debug)
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

	// store atomic levels for runtime log level changes
	c.atomicLogLevels = append(c.atomicLogLevels,
		collectorLevel,
		resolversLevel,
		ioLevel,
		decoderLevel,
		reassemblyLevel,
		dbLevel,
	)

	// create errors.log file
	c.mu.Lock()
	c.errorLogFile, err = os.Create(filepath.Join(c.config.DecoderConfig.Out, "errors.log"))
	c.mu.Unlock()

	return nil
}
