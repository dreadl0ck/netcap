package transform

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/maltego"
)

// dieIfExecutable can be used to check if the file at the passed in location is executable
// if so, the function will crash the program and print an error for maltego.
func dieIfExecutable(trx *maltego.Transform, loc string) {
	// the open tool uses the file extension to decide which program to pass the file to
	// if there is an extension for known executable formats - abort
	ext := filepath.Ext(loc)
	log.Println("file extension", ext)

	if ext == ".exe" || ext == ".bin" {
		log.Println("detected known executable file extension - aborting to prevent accidental execution!")
		trx.AddUIMessage("completed!", maltego.UIMessageInform)
		fmt.Println(trx.ReturnOutput())

		return
	}

	// if there is no extension, use content type detection to determine if its an executable
	// TODO: improve and test content type check and executable file detection
	log.Println("open path for determining content type:", loc)

	f, err := os.OpenFile(loc, os.O_RDONLY, defaults.DirectoryPermission)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	buf := make([]byte, 512)

	_, err = io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Fatal(err)
	}

	// check if file is executable to prevent accidental execution
	cType := http.DetectContentType(buf)
	log.Println("cType:", cType)

	stat, err := os.Stat(loc)
	if err != nil {
		log.Fatal(err)
	}

	if cType == octetStream && isExecAny(stat.Mode()) {
		log.Println("detected executable file - aborting to prevent accidental execution!")
		trx.AddUIMessage("completed!", maltego.UIMessageInform)
		fmt.Println(trx.ReturnOutput())

		return
	}
}
