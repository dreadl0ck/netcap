/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package label

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/utils"
	pb "gopkg.in/cheggaaa/pb.v1"
)

var (
	UseProgressBars   = false
	ClassificationMap = make(map[string]int)
	excluded          = make(map[string]bool)
)

// SetExcluded takes a comma separated list of strings to exclude from labeling
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

func finish(wg *sync.WaitGroup, r *netcap.Reader, f *os.File, labelsTotal int, outFileName string, progress *pb.ProgressBar) {

	// only add to summary if labels were added and no progress bars are being used
	if labelsTotal != 0 && !UseProgressBars {
		fmt.Println(" + " + utils.Pad(filepath.Base(f.Name()), 40) + "labels: " + strconv.Itoa(labelsTotal))
	}

	if UseProgressBars {
		progress.Finish()
	}

	err := r.Close()
	if err != nil {
		panic(err)
	}

	err = f.Sync()
	if err != nil {
		panic(err)
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	// remove file that did not have any matching labels
	if labelsTotal == 0 {
		err := os.Remove(outFileName)
		if err != nil {
			panic(err)
		}
	}

	wg.Done()
}
