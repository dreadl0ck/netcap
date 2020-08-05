package transform

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
)

func ToCaptureProcess() {

	lt := maltego.ParseLocalArguments(os.Args[1:])
	log.Println("capture on interface:", lt.Value)

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	outDir := filepath.Join(home, lt.Value+".net")
	log.Println("writing output to:", outDir)

	// TODO: pass bpf (add as property to Interface entity)
	args := []string{"capture", "-iface", lt.Value, "-out", outDir, "-fileStorage=files", "-config=/usr/local/etc/netcap/livecapture.conf", "-quiet"}
	log.Println("args:", args)

	cmd := exec.Command("/usr/local/bin/net", args...)
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("PID", cmd.Process.Pid)

	returnCaptureProcessEntity(cmd.Process.Pid, outDir, lt.Value)
}

func returnCaptureProcessEntity(pid int, path string, iface string) {

	pidStr := strconv.Itoa(pid)

	// generate maltego transform
	trx := maltego.Transform{}

	name := "Capture Process" + "\nPID: " + pidStr
	ent := trx.AddEntity("netcap.CaptureProcess", name)

	ent.AddProperty("pid", "PID", "strict", pidStr)
	ent.AddProperty("path", "Path", "strict", path)
	ent.AddProperty("iface", "Interface", "strict", iface)

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
