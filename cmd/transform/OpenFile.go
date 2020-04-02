package main

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
)

func OpenFile() {

	var (
		lt = maltego.ParseLocalArguments(os.Args)
		trx = &maltego.MaltegoTransform{}
		openCommandName = os.Getenv("NETCAP_MALTEGO_OPEN_FILE_CMD")
		args []string
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

	log.Println("open path:", lt.Values["path"])
	f, err := os.OpenFile(lt.Values["path"], os.O_RDONLY, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var buf = make([]byte, 512)
	_, err = io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		log.Fatal(err)
	}

	// check if file is executable
	ctype := http.DetectContentType(buf)
	log.Println("ctype:", ctype)
	if ctype == "application/octet-stream" {
		trx.AddUIMessage("completed!","Inform")
		fmt.Println(trx.ReturnOutput())
		return
	}

	log.Println("command for opening files:", openCommandName)
	args = append(args, lt.Values["path"])

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}