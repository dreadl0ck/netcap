package main

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
)

func OpenFile() {

	lt := maltego.ParseLocalArguments(os.Args)
	trx := &maltego.MaltegoTransform{}

	log.Println("path:", lt.Values["path"])

	out, err := exec.Command("open", lt.Values["path"]).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}