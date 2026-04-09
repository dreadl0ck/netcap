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

package io

import (
	"bufio"
	"compress/gzip"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// Reader implements reading netcap audit record files.
type Reader struct {
	file    *os.File
	bReader *bufio.Reader
	gReader *gzip.Reader
	dReader *delimited.Reader
}

// Open a netcap audit record file for reading.
func Open(file string, memBufSize int) (*Reader, error) {
	r := &Reader{}

	h, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	if memBufSize <= 0 {
		memBufSize = defaults.BufferSize
	}

	r.file = h
	r.bReader = bufio.NewReaderSize(h, memBufSize)

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

// Close the file.
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

// Next Message.
func (r *Reader) Next(msg proto.Message) error {
	return r.dReader.NextProto(msg)
}

// ReadHeader reads the file header.
func (r *Reader) ReadHeader() (*types.Header, error) {
	// read netcap header
	var (
		header = new(types.Header)
		err    = r.Next(header)
	)

	if err != nil {
		return nil, errors.New("invalid netcap header in file: " + r.file.Name() + ", error: " + err.Error())
	}

	return header, nil
}
