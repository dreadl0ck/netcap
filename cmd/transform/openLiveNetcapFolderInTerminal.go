package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
)

func openLiveNetcapFolderInTerminal() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		openCommandName, args = createOpenTerminalCommand(
			[]string{getPathLiveCaptureOutDir(lt.Values["name"])},
		)
	)

	log.Println("vals", lt.Values)
	log.Println("command for opening path:", openCommandName)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
