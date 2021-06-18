/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2019 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label/manager"
	"github.com/dreadl0ck/netcap/types"
	gzip "github.com/klauspost/pgzip"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/utils"
)

// CustomMap uses info from a csv file to label the data
// func customMap(wg *sync.WaitGroup, file string, typ string, labelMap map[int64]*suricataAlert, labels []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {.
func CustomMap(man *manager.LabelManager, wg *sync.WaitGroup, file, typ string, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, file)
		total, errCount = netio.Count(fname)
		labelsTotal     = 0
		outFileName     = filepath.Join(outDir, typ+"_labeled.csv.gz")
		progress        = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
	)
	if errCount != nil {
		log.Fatal("failed to count audit records:", errCount)
	}

	go func() {
		// open layer data file
		r, err := netio.Open(fname, defaults.BufferSize)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header, errFileHeader := r.ReadHeader()
		if errFileHeader != nil {
			log.Fatal(errFileHeader)
		}

		// create outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		gzipWriter := gzip.NewWriter(f)

		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// you would like to utilize, but about twice the number of blocks would be the best.
		if err = gzipWriter.SetConcurrency(defaults.CompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}

		var (
			record = netio.InitRecord(header.Type)
			ok     bool
			p      types.AuditRecord
		)

		// check if we can decode it as CSV
		if p, ok = record.(types.AuditRecord); !ok {
			panic("type does not implement types.AuditRecord interface:" + typ)
		}

		// run selection
		types.Select(record, selection)

		// write header
		_, err = gzipWriter.Write([]byte(strings.Join(p.CSVHeader(), separator) + separator + "result" + "\n"))
		if err != nil {
			panic(err)
		}

		for {
			err = r.Next(record)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			labelsTotal = applyLabel(man, p, gzipWriter, separator, typ, labelsTotal)
		}

		err = gzipWriter.Flush()
		if err != nil {
			log.Fatal(err)
		}

		err = gzipWriter.Close()
		if err != nil {
			log.Fatal(err)
		}

		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}

func applyLabel(man *manager.LabelManager, record types.AuditRecord, writer io.Writer, separator string, typ string, labelsTotal int) int {

	label := man.Label(record)

	if len(label) != 0 {
		if strings.HasPrefix(label, " |") {
			log.Fatal("invalid label: ", label)
		}

		// add label
		_, _ = writer.Write([]byte(strings.Join(record.CSVRecord(), separator) + separator + label + "\n"))
		labelsTotal++
	} else {
		// label as normal
		_, _ = writer.Write([]byte(strings.Join(record.CSVRecord(), separator) + separator + "normal\n"))
	}

	return labelsTotal
}

// CustomLabels uses info from a csv file to label the data.
func CustomLabels(pathMappingInfo, outputPath, separator, selection string) error {
	var (
		start = time.Now()
		// TODO: make scatter configurable
		man = manager.NewLabelManager(UseProgressBars, Debug, removeFilesWithoutMatches, false, 5*time.Minute)
	)

	man.Init(pathMappingInfo)

	// apply labels to data
	// set outDir to current dir or flagOut
	var outDir string
	if outputPath != "" {
		outDir = outputPath
	} else {
		outDir = "."
	}

	// label all layer data in outDir
	// first read directory
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		return err
	}

	var (
		wg  sync.WaitGroup
		pbs []*pb.ProgressBar
	)

	// iterate over all files in dir
	for _, f := range files {
		// check if its an audit record file
		if strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) || strings.HasSuffix(f.Name(), defaults.FileExtension) {
			wg.Add(1)

			var (
				// get record name
				filename = f.Name()
				typ      = strings.TrimSuffix(strings.TrimSuffix(filename, defaults.FileExtensionCompressed), defaults.FileExtension)
			)

			// fmt.Println("type", typ)
			pbs = append(pbs, CustomMap(man, &wg, filename, typ, outputPath, separator, selection))
		}
	}

	var pool *pb.Pool
	if UseProgressBars { // wait for goroutines to start and initialize
		// otherwise progress bars will bug
		time.Sleep(3 * time.Second)

		// start pool
		pool, err = pb.StartPool(pbs...)
		if err != nil {
			return err
		}
		utils.ClearScreen()
	}

	wg.Wait()

	if UseProgressBars {
		// close pool
		if err = pool.Stop(); err != nil {
			fmt.Println("failed to stop progress bar pool:", err)
		}
	}

	fmt.Println("\ndone in", time.Since(start))
	return nil
}
