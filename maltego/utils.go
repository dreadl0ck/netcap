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

package maltego

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dreadl0ck/maltego"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
)

const (
	errUnexpectedFileType    = "unexpected file type"
	errUnexpectedReadFailure = "unexpected read failure"

	// ExecutablePath points to the netcap binary on disk
	ExecutablePath = "/usr/local/bin/net"

	// PropertyIpAddr is the name of maltego property that contains the IP address
	PropertyIpAddr = "ipaddr"

	// PropertyIpAddrLabel is the label for the ip address property
	PropertyIpAddrLabel = "IPAddress"
)

func openFile(path string) (*os.File, string) {
	log.Println("open path:", path)
	f, err := os.Open(path)
	if err != nil {

		log.Println("failed to open path", err, "trying without .gz extension...")

		f, err = os.Open(strings.TrimSuffix(path, ".gz"))
		if err != nil {
			log.Println("failed to open path", err)
			trx := &maltego.Transform{}
			trx.AddUIMessage("failed to open path: "+err.Error(), maltego.UIMessageInform)
			fmt.Println(trx.ReturnOutput())
			os.Exit(0) // don't signal an error for the transform invocation
		}
	}

	return f, path
}

func openNetcapArchive(path string) *netio.Reader {
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {

		log.Println("failed to open path ", path, " trying without .gz extension...")
		path = strings.TrimSuffix(path, ".gz")

		r, err = netio.Open(path, defaults.BufferSize)
		if err != nil {
			maltego.Die(err.Error(), "failed to open file")
		}
	}

	return r
}
