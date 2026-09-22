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
