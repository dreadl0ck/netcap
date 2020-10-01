package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
	"strings"
)

func openNetcapFolderInTerminal() {
	var (
		lt                    = maltego.ParseLocalArguments(os.Args)
		trx                   = &maltego.Transform{}
		openCommandName, args = createOpenTerminalCommand(
			[]string{
				strings.TrimPrefix(lt.Values["path"], "file://") + ".net",
			},
		)
	)

	log.Println("vals", lt.Values)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		die(err.Error(), string(out))
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
