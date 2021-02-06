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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// dieIfExecutable can be used to check if the file at the passed in location is executable
// if so, the function will exit the program cleanly and print an error for maltego.
func dieIfExecutable(loc string) {
	// the open tool uses the file extension to decide which program to pass the file to
	// if there is an extension for known executable formats - abort directly
	ext := filepath.Ext(loc)
	log.Println("file extension", ext)

	if ext == ".exe" || ext == ".bin" {
		maltego.Die("detected known executable file extension", "aborting to prevent accidental execution")
	}

	// if there is no extension, use content type detection to determine if its an executable
	log.Println("open path for determining content type:", loc)

	f, err := os.OpenFile(loc, os.O_RDONLY, defaults.DirectoryPermission)
	if err != nil {
		maltego.Die(err.Error(), "failed to open path")
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	// read file banner to determine content type
	buf := make([]byte, 512)
	_, err = io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			maltego.Die(err.Error(), "failed to read file banner")
		}
		// unexpected EOF: we got less than 512 bytes of data
		// read the entire thing and update the buffer
		buf, err = ioutil.ReadAll(f)
		if err != nil {
			maltego.Die(err.Error(), "failed to read file")
		}
	}

	// check if file is executable to prevent accidental execution
	cType := http.DetectContentType(buf)
	log.Println("cType:", cType)

	// get file stats to determine if executable bit is set
	stat, err := os.Stat(loc)
	if err != nil {
		maltego.Die(err.Error(), "failed to stat file")
	}
	if stat != nil {
		// if content type is octet or the file has the executable bit set, abort
		if cType == octetStream || isExecAny(stat.Mode()) {
			maltego.Die("detected executable file format", "aborting to prevent accidental execution")
		}
	}
}

//func Die(err string, msg string) {
//	trx := &maltego.Transform{}
//	// add error message for the user
//	trx.AddUIMessage(maltego.EscapeText(msg+": "+err), maltego.UIMessageFatal)
//	fmt.Println(trx.ReturnOutput())
//	log.Println(msg, err)
//	os.Exit(0) // don't signal an error for the transform invocation
//}

func createJa3TableHTML(m map[string]string) string {
	out := []string{"<table style='width:100%'>"}

	out = append(out, `<tr>
    <th>Ja3</th>
    <th>Lookup Result</th>
  </tr>`)

	for k, v := range m {
		if v != "" {
			out = append(out, "<tr><td style='color:red'>"+k+"</td><td>"+v+"</td></tr>")
		} else {
			out = append(out, "<tr><td>"+k+"</td><td>"+v+"</td></tr>")
		}
	}

	out = append(out, "</table>")

	return strings.Join(out, "")
}

func createSNITableHTML(m map[string]int64) string {
	out := []string{"<table style='width:100%'>"}

	out = append(out, `<tr>
    <th>SNI</th>
    <th>Number of Packets</th>
  </tr>`)

	var snis sniSlice
	for k, v := range m {
		snis = append(snis, &sni{
			name:       k,
			numPackets: v,
		})
	}

	sort.Sort(snis)

	for _, s := range snis {
		out = append(out, "<tr><td>"+s.name+"</td><td>"+strconv.FormatInt(s.numPackets, 10)+"</td></tr>")
	}

	out = append(out, "</table>")

	return strings.Join(out, "")
}

func createProtocolsTableHTML(m map[string]*types.Protocol) string {
	out := []string{"<table style='width:100%'>"}

	out = append(out, `<tr>
    <th>Application</th>
	<th>Category</th>
    <th>Number of Packets</th>
  </tr>`)

	for k, v := range m {
		out = append(out, "<tr><td>"+k+"</td><td>"+v.Category+"</td><td>"+strconv.FormatUint(v.Packets, 10)+"</td></tr>")
	}

	out = append(out, "</table>")

	return strings.Join(out, "")
}

func createPortsTableHTML(ports []*types.Port) string {
	out := []string{"<table style='width:100%'>"}

	out = append(out, `<tr>
    <th>PortNumber</th>
	<th>Packets</th>
    <th>Bytes</th>
	<th>Protocol</th>
  </tr>`)

	sort.Sort(portSlice(ports))

	for _, p := range ports {
		out = append(out, "<tr><td>"+strconv.Itoa(int(p.PortNumber))+"</td><td>"+strconv.FormatUint(p.Stats.Packets, 10)+"</td><td>"+strconv.FormatUint(p.Stats.Bytes, 10)+"</td><td>"+p.Protocol+"</td></tr>")
	}

	out = append(out, "</table>")

	return strings.Join(out, "")
}

// portSlice implements sort.Interface to sort port stats fragments based on the number of bytes transferred.
type portSlice []*types.Port

// Len returns the length.
func (d portSlice) Len() int {
	return len(d)
}

// Less will check if the value at index i is less than the one at index j.
func (d portSlice) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]

	return data1.Stats.Bytes < data2.Stats.Bytes
}

// Swap will flip both values.
func (d portSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

type sni struct {
	name       string
	numPackets int64
}

// sniSlice implements sort.Interface
type sniSlice []*sni

// Len returns the length.
func (d sniSlice) Len() int {
	return len(d)
}

// Less will check if the value at index i is less than the one at index j.
func (d sniSlice) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]

	return data1.numPackets < data2.numPackets
}

// Swap will flip both values.
func (d sniSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// addEntityWithPath adds an entity to the transform.
func addEntityWithPath(tr *maltego.Transform, enType, value, path string) *maltego.Entity {

	// ensure response message is initialized
	if tr.ResponseMessage == nil {
		tr.ResponseMessage = &maltego.ResponseMessage{}
	}

	ent := maltego.NewEntity(enType, maltego.EscapeText(value), "100")
	ent.AddProperty("path", "Path", maltego.Strict, path)
	tr.ResponseMessage.Entities.Items = append(tr.ResponseMessage.Entities.Items, ent)

	return ent
}
