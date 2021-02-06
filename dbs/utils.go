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

package dbs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dustin/go-humanize"
)

func calculateDirectorySize(path string) (size int64, err error) {
	err = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func saveTotalDatabaseSize(path string) {
	size, err := calculateDirectorySize(path)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("saving total db size to:", filepath.Join(path, "size"))
	f, err := os.Create(filepath.Join(path, "size"))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.WriteString(humanize.Bytes(uint64(size)))
	if err != nil {
		log.Fatal(err)
	}
}
