package transform

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/dreadl0ck/netcap/maltego"
)

func openLiveNetcapFolderInTerminal() {
	var (
		lt                    = maltego.ParseLocalArguments(os.Args[1:])
		trx                   = &maltego.Transform{}
		openCommandName, args = createOpenTerminalCommand(
			[]string{getPathLiveCaptureOutDir(lt.Value)},
		)
	)

	log.Println("vals", lt.Values)
	log.Println("command for opening path:", openCommandName)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		die(err.Error(), string(out))
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
