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

package transform

import (
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/dreadl0ck/maltego"
)

func toNetworkInterfaces() {
	trx := &maltego.Transform{}

	// get interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		maltego.Die(err.Error(), "failed to get network interfaces")
	}

	for _, nic := range interfaces {
		log.Println(nic.Index, nic.Name, nic.Flags, nic.HardwareAddr, nic.MTU)

		ent := trx.AddEntity("netcap.Interface", nic.Name)
		ent.AddProperty("properties.interface", "Interface", maltego.Strict, nic.Name)
		ent.AddProperty("index", "Index", maltego.Strict, strconv.Itoa(nic.Index))
		ent.AddProperty("hardwareaddr", "HardwareAddr", maltego.Strict, nic.HardwareAddr.String())
		ent.AddProperty("mtu", "MTU", maltego.Strict, strconv.Itoa(nic.MTU))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
