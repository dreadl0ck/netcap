package transform

import (
	"errors"
	"fmt"
	"github.com/dreadl0ck/netcap/types"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/maltego"
)

// dieIfExecutable can be used to check if the file at the passed in location is executable
// if so, the function will exit the program cleanly and print an error for maltego.
func dieIfExecutable(loc string) {
	// the open tool uses the file extension to decide which program to pass the file to
	// if there is an extension for known executable formats - abort directly
	ext := filepath.Ext(loc)
	log.Println("file extension", ext)

	if ext == ".exe" || ext == ".bin" {
		die("detected known executable file extension", "aborting to prevent accidental execution")
	}

	// if there is no extension, use content type detection to determine if its an executable
	log.Println("open path for determining content type:", loc)

	f, err := os.OpenFile(loc, os.O_RDONLY, defaults.DirectoryPermission)
	if err != nil {
		die(err.Error(), "failed to open path")
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
			die(err.Error(), "failed to read file banner")
		}
		// unexpected EOF: we got less than 512 bytes of data
		// read the entire thing and update the buffer
		buf, err = ioutil.ReadAll(f)
		if err != nil {
			die(err.Error(), "failed to read file")
		}
	}

	// check if file is executable to prevent accidental execution
	cType := http.DetectContentType(buf)
	log.Println("cType:", cType)

	// get file stats to determine if executable bit is set
	stat, err := os.Stat(loc)
	if err != nil {
		die(err.Error(), "failed to stat file")
	}

	// if content type is octet or the file has the executable bit set, abort
	if cType == octetStream || isExecAny(stat.Mode()) {
		die("detected executable file format", "aborting to prevent accidental execution")
	}
}

func die(err string, msg string) {
	trx := maltego.Transform{}
	// add error message for the user
	trx.AddUIMessage(maltego.EscapeText(msg+": "+err), maltego.UIMessageFatal)
	fmt.Println(trx.ReturnOutput())
	log.Println(msg, err)
	os.Exit(0) // don't signal an error for the transform invocation
}

func createJa3TableHTML(m map[string]string) string {

	var out = []string{"<table style='width:100%'>"}

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

	var out = []string{"<table style='width:100%'>"}

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

	var out = []string{"<table style='width:100%'>"}

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

	var out = []string{"<table style='width:100%'>"}

	out = append(out, `<tr>
    <th>PortNumber</th>
	<th>Packets</th>
    <th>Bytes</th>
	<th>Protocol</th>
  </tr>`)

	sort.Sort(portSlice(ports))

	for _, p := range ports {
		out = append(out, "<tr><td>"+strconv.Itoa(int(p.PortNumber))+"</td><td>"+strconv.FormatUint(p.Packets, 10)+"</td><td>"+strconv.FormatUint(p.Bytes, 10)+"</td><td>"+p.Protocol+"</td></tr>")
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

	return data1.Bytes < data2.Bytes
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
