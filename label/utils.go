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

// Package label implements mapping alerts from suricata to netcap audit records
package label

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cheggaaa/pb"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	// UseProgressBars whether to use the progress bar.
	UseProgressBars = false
	// classificationMap map of classifications.
	classificationMap = make(map[string]int)
	excluded          = make(map[string]bool)

	// Debug mode.
	Debug bool

	removeFilesWithoutMatches = false
)

func debug(args ...interface{}) {
	if Debug {
		fmt.Println(args...)
	}
}

// SetExcluded takes a comma separated list of strings to exclude from labeling.
func SetExcluded(arg string) {
	if arg != "" {
		if strings.Contains(arg, ",") {
			vals := strings.Split(arg, ",")
			if len(vals) < 2 {
				log.Fatal("invalid list", vals)
			}

			for _, v := range vals {
				excluded[v] = true
			}
		} else {
			excluded[arg] = true
		}
	}
}

func die(err string, msg string) {
	log.Fatal(err, msg)
}

func finish(wg *sync.WaitGroup, r *io.Reader, f *os.File, labelsTotal int, outFileName string, progress *pb.ProgressBar) {
	if UseProgressBars {
		progress.Finish()
	}

	// only add to summary if labels were added and no progress bars are being used
	if labelsTotal != 0 && !UseProgressBars {
		fmt.Println(" + " + utils.Pad(filepath.Base(f.Name()), 40) + "labels: " + strconv.Itoa(labelsTotal))
	}

	if err := r.Close(); err != nil {
		log.Fatal("failed to close netcap reader for", outFileName, ", error:", err)
	}

	if err := f.Sync(); err != nil {
		log.Fatal("failed to sync", outFileName, ", error:", err)
	}

	if err := f.Close(); err != nil {
		log.Fatal("failed to close", outFileName, ", error:", err)
	}

	if //goland:noinspection GoBoolExpressions
	removeFilesWithoutMatches {
		// remove file that did not have any matching labels
		if labelsTotal == 0 {
			if err := os.Remove(outFileName); err != nil {
				log.Fatal("failed remove empty file", outFileName, ", error:", err)
			}
		}
	}

	wg.Done()
}
