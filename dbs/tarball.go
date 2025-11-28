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
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
)

/*
 * Create Tarballs
 */

// makeTarball will create a compressed tarball
func makeTarball(source string, revision string, buf io.Writer) error {

	// tar -> gzip -> buffer
	var (
		zipWriter         = gzip.NewWriter(buf)
		tarWriter         = tar.NewWriter(zipWriter)
		fileCount         int
		dirCount          int
		exploitdbIncluded bool
	)

	// process every file in the source folder
	err := filepath.Walk(source, func(file string, fi os.FileInfo, err error) error {

		// generate tar header for archive
		hdr, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return err
		}

		// provide the real file name
		// (see https://golang.org/src/archive/tar/common.go?#L626)
		hdr.Name = strings.ReplaceAll(filepath.ToSlash(file), source, revision)

		// Track if exploitdb directory is being included
		if fi.IsDir() && fi.Name() == "exploitdb" {
			exploitdbIncluded = true
			fmt.Println("✓ Including exploitdb folder with exploit code snippets")
		}

		// write header in archive
		if err = tarWriter.WriteHeader(hdr); err != nil {
			return err
		}

		// if not a directory, write file content
		if !fi.IsDir() {
			fileCount++

			f, errOpen := os.Open(file)
			if errOpen != nil {
				return errOpen
			}
			defer func() {
				errClose := f.Close()
				if errClose != nil {
					log.Fatal(errClose)
				}
			}()

			fmt.Println("adding", f.Name())
			if _, err = io.Copy(tarWriter, f); err != nil {
				return err
			}
		} else {
			dirCount++
		}
		return nil
	})
	if err != nil {
		log.Fatalln("failed to collect files: ", err)
	}

	fmt.Printf("Tarball contains: %d files, %d directories\n", fileCount, dirCount)
	if exploitdbIncluded {
		fmt.Println("✓ exploitdb folder successfully bundled in archive")
	}

	// produce tarball
	if err = tarWriter.Flush(); err != nil {
		return err
	}
	if err = tarWriter.Close(); err != nil {
		return err
	}

	// produce gzip archive
	if err = zipWriter.Flush(); err != nil {
		return err
	}
	if err = zipWriter.Close(); err != nil {
		return err
	}

	return nil
}

/*
 * Deflate Tarballs
 */

// unpackTarball reads from src and unpacks to the path dst
// it returns the name of the unpacked archive and an error
func unpackTarball(source io.Reader, destination string) (string, error) {

	var name string

	// ungzip archive
	zr, err := gzip.NewReader(source)
	if err != nil {
		return name, err
	}

	// deflate tarball
	tarReader := tar.NewReader(zr)

	// uncompress each element in the tarball
	for {
		// get next element
		hdr, errNext := tarReader.Next()
		if errNext == io.EOF {
			return name, nil
		}
		if errNext != nil {
			return name, errNext
		}

		target := destination

		// validate name against path traversal
		if !isValidRelativePath(hdr.Name) {
			return name, fmt.Errorf("tar contained invalid name error %q\n", target)
		}

		fmt.Println(hdr.Name)

		// get archive name from path of first element
		if name == "" {
			name = hdr.Name
		}

		// add dst + re-format slashes according to system
		target = filepath.Join(destination, hdr.Name)

		// check the type
		switch hdr.Typeflag {

		// if its a directory and it doesn't exist yet create it
		case tar.TypeDir:
			// check if target exists already
			if _, err = os.Stat(target); err != nil {
				if err = os.MkdirAll(target, defaults.DirectoryPermission); err != nil {
					return name, err
				}
			}
		// if it's a file create it (with same permission)
		case tar.TypeReg:
			f, errOpen := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(hdr.Mode))
			if errOpen != nil {
				return name, errOpen
			}

			// copy over the contents
			if _, err = io.Copy(f, tarReader); err != nil && err != io.EOF {
				return name, err
			}

			// close the file
			err = f.Close()
			if err != nil {
				return name, err
			}
		}
	}
}

/*
 * Utils
 */

// check for path traversal and correct forward slashes
func isValidRelativePath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
}
