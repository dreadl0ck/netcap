package transform

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
)

func StopCaptureProcess() {

	lt := maltego.ParseLocalArguments(os.Args[1:])
	pid := lt.Values["pid"]
	log.Println("kill PID:", pid)

	pidInt, err := strconv.Atoi(pid)
	if err != nil {
		log.Fatal(err)
	}

	p, err := os.FindProcess(pidInt)
	if err != nil {
		log.Fatal(err)
	}

	// graceful shutdown
	// TODO: add windows support
	err = p.Signal(os.Interrupt)
	//err = p.Kill()
	if err != nil {
		log.Fatal(err)
	}

	// generate maltego transform
	trx := maltego.Transform{}
	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
