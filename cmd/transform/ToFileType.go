package transform

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/dreadl0ck/netcap/maltego"
)

func toFileType() {
	lt := maltego.ParseLocalArguments(os.Args)
	trx := &maltego.Transform{}
	path := lt.Values["path"]

	log.Println("path:", lt.Values["path"])

	out, err := exec.Command("file", "-b", path).CombinedOutput()
	if err != nil {
		die(err.Error(), string(out))
	}

	trx.AddEntityWithPath("netcap.FileType", string(out), path)
	fmt.Println(trx.ReturnOutput())
}
