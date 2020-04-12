package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
)

func GetFileType() {

	lt := maltego.ParseLocalArguments(os.Args)
	trx := &maltego.MaltegoTransform{}

	log.Println("path:", lt.Values["path"])

	out, err := exec.Command("file", "-b", lt.Values["path"]).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}

	name := maltego.EscapeText(string(out))
	ent := trx.AddEntity("netcap.FileType", name)
	ent.SetType("netcap.FileType")
	ent.SetValue(name)
	ent.SetLinkColor("#000000")

	fmt.Println(trx.ReturnOutput())
}
