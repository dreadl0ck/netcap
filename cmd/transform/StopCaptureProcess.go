package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"strconv"
	"syscall"
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
	err = p.Signal(syscall.SIGINT)
	//err = p.Kill()
	if err != nil {
		log.Fatal(err)
	}

	// generate maltego transform
	trx := maltego.MaltegoTransform{}
	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}

