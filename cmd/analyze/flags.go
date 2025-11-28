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

package main

import (
	"flag"
	"runtime"
)

var (
	// commandline flags
	flagAttackList            = flag.String("attacks", "", "attack list CSV")
	flagInput                 = flag.String("in", ".", "input directory (default is current directory)")
	flagOut                   = flag.String("out", ".", "output path")
	flagNumWorkers            = flag.Int("workers", runtime.NumCPU(), "number of parallel processed files")
	flagMaxFiles              = flag.Int("max", 0, "max number of processed files")
	flagDebug                 = flag.Bool("debug", false, "toggle debug mode")
	flagReuseLineBuffer       = flag.Bool("reuse", true, "reuse CSV line buffer")
	flagSkipIncompleteRecords = flag.Bool("skip-incomplete", false, "skip lines that contain empty values")
	flagZeroIncompleteRecords = flag.Bool("zero-incomplete", true, "skip lines that contain empty values")
	flagCountAttacks          = flag.Bool("count-attacks", false, "count attacks")
	flagColumnSummaries       = flag.String("colsums", "", "column summary JSON file for loading")
	flagAnalyzeOnly           = flag.Bool("analyze-only", false, "analyze only")
	flagPathSuffix            = flag.String("suffix", "_sorted.csv", "suffix for all csv files to be parsed")
	flagOffset                = flag.Int("offset", 0, "index offset from which file to start")
	flagFileFilter            = flag.String("file-filter", "", "supply a text file with newline separated filenames to process")
	flagVersion               = flag.Bool("version", false, "print version")
	flagZScore                = flag.Bool("zscore", false, "use zscore for normalization")
	flagEncode                = flag.Bool("encode", true, "encode the values to numeric format")
	flagEncodeCategoricals    = flag.Bool("encodeCategoricals", true, "encode the categorical values to numeric format")
	flagNormalizeCategoricals = flag.Bool("normalizeCategoricals", true, "normalize the categorical values after encoding them to numeric format")
)
