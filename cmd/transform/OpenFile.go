package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func OpenFile() {

	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		openCommandName = os.Getenv("NC_MALTEGO_OPEN_FILE_CMD")
		args            []string
	)

	// if no command has been supplied via environment variable
	// then default to:
	// - open for macOS
	// - gio open for linux
	if openCommandName == "" {
		if runtime.GOOS == "darwin" {
			openCommandName = "open"
		} else { // linux
			openCommandName = "gio"
			args = append(args, "open")
		}
	}

	loc := lt.Values["location"]

	// the open tool uses the file extension to decide which program to pass the file to
	// if there is an extension for known executable formats - abort
	ext := filepath.Ext(loc)
	log.Println("file extension", ext)
	if ext == ".exe" || ext == ".bin" {
		log.Println("detected known executable file extension - aborting to prevent accidental execution!")
		trx.AddUIMessage("completed!", "Inform")
		fmt.Println(trx.ReturnOutput())
		return
	}
	// if there is no extension, use content type detection to determine if its an executable
	// TODO: improve and test content type check and executable file detection
	log.Println("open path for determining content type:", loc)
	f, err := os.OpenFile(lt.Values["location"], os.O_RDONLY, outDirPermission)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var buf = make([]byte, 512)
	_, err = io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		log.Fatal(err)
	}

	// check if file is executable to prevent accidental execution
	ctype := http.DetectContentType(buf)
	log.Println("ctype:", ctype)

	stat, err := os.Stat(lt.Values["location"])
	if err != nil {
		log.Fatal(err)
	}
	if ctype == "application/octet-stream" && IsExecAny(stat.Mode()) {
		log.Println("detected executable file - aborting to prevent accidental execution!")
		trx.AddUIMessage("completed!", "Inform")
		fmt.Println(trx.ReturnOutput())
		return
	}

	args = append(args, loc)
	log.Println("final command for opening files:", openCommandName, args)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}

func IsExecAny(mode os.FileMode) bool {
	return mode&0111 != 0
}
