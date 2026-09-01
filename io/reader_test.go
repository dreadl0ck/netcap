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
	"errors"
	"io"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

func TestReader(t *testing.T) {
	requireTestAuditRecord(t)

	r, err := Open("../tests/testdata/TCP.ncap.gz", defaults.BufferSize)
	if err != nil {
		t.Fatal(err)
	}

	header, errHeader := r.ReadHeader()
	if errHeader != nil {
		t.Fatal("failed to read header")
	}

	if header.Type != types.Type_NC_TCP {
		t.Fatal("not TCP, got: ", header.Type)
	}

	var (
		tcp   = InitRecord(header.Type)
		count int
	)

	for {
		err = r.Next(tcp)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		count++
	}

	if count != 3196 {
		t.Fatal("expected 3196 audit records, got: ", count)
	}
}
