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
