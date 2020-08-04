package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
)

func ToFileType() {

	lt := maltego.ParseLocalArguments(os.Args)
	trx := &maltego.Transform{}

	log.Println("path:", lt.Values["path"])

	out, err := exec.Command("file", "-b", lt.Values["path"]).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}

	trx.AddEntity("netcap.FileType", string(out))
	fmt.Println(trx.ReturnOutput())
}
