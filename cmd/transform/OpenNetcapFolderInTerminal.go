package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
)

func openNetcapFolderInTerminal() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		openCommandName, args = createOpenTerminalCommand(
			[]string{lt.Values["path"] + ".net"},
		)
	)

	log.Println("vals", lt.Values)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
