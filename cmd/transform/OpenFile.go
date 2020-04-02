package main

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"log"
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

	log.Println("command for opening files:", openCommandName)
	log.Println("open path:", lt.Values["path"])
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