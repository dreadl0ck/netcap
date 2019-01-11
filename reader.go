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

package netcap

import (
	"bufio"
	"compress/gzip"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/types"
	proto "github.com/golang/protobuf/proto"
	"kythe.io/kythe/go/platform/delimited"
)

// Reader implements reading netcap files
type Reader struct {
	file    *os.File
	bReader *bufio.Reader
	gReader *gzip.Reader
	dReader *delimited.Reader
}

// Open a file
func Open(file string) (*Reader, error) {
	r := &Reader{}

	h, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	r.file = h
	r.bReader = bufio.NewReader(h)

	if filepath.Ext(file) == ".gz" {
		r.gReader, err = gzip.NewReader(r.bReader)
		if err != nil {
			return nil, err
		}
		r.dReader = delimited.NewReader(r.gReader)
	} else {
		r.dReader = delimited.NewReader(r.bReader)
	}

	return r, nil
}

// Close the file
func (r *Reader) Close() error {
	if r.gReader != nil {
		err := r.gReader.Close()
		if err != nil {
			return err
		}
	}
	err := r.file.Sync()
	if err != nil {
		return err
	}
	return r.file.Close()
}

// Next Message
func (r *Reader) Next(msg proto.Message) error {
	return r.dReader.NextProto(msg)
}

// ReadHeader reads the file header
func (r *Reader) ReadHeader() *types.Header {
	// read netcap header
	var (
		header = new(types.Header)
		err    = r.Next(header)
	)
	if err != nil {
		panic("invalid netcap header in file: " + r.file.Name() + ", error: " + err.Error())
	}
	return header
}
