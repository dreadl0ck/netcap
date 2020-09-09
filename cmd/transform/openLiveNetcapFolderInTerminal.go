package transform

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"github.com/dreadl0ck/netcap/env"
	"github.com/dreadl0ck/netcap/maltego"
)

func openLiveNetcapFolderInTerminal() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		openCommandName = os.Getenv(env.MaltegoOpenTerminalCommand)
		args            []string
	)

	// if no command has been supplied via environment variable
	// then default to:
	// - open for macOS
	// - gio open for linux
	if openCommandName == "" {
		if runtime.GOOS == platformDarwin {
			openCommandName = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
		} else { // linux TODO:
			openCommandName, args = makeLinuxCommand(defaultOpenCommandLinux, args)
		}
	}

	log.Println("vals", lt.Values)
	path := getPathLiveCaptureOutDir(lt.Values["name"])



	log.Println("command for opening path:", openCommandName)
	args = append(args, path)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
