package transform

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/maltego"
)

func toCaptureProcess() {

	var (
		lt    = maltego.ParseLocalArguments(os.Args[1:])
		snapL int
	)
	log.Println("capture on interface:", lt.Value)

	// check if a custom snaplen was provided as property
	if snaplen, ok := lt.Values["snaplen"]; ok {
		if snaplen != "" {
			n, err := strconv.Atoi(snaplen)
			if err != nil {
				die(err.Error(), "invalid snaplen provided")
			}

			if n <= 0 {
				die("invalid snaplen", "snaplen must not be <= 0")
			}

			snapL = n
		}
	}

	outDir := getPathLiveCaptureOutDir(lt.Value)
	log.Println("writing output to:", outDir)

	iface := lt.Value

	// on windows the interface transport identifier must be used to attach
	// we have to retrieve it by calling getmac
	if runtime.GOOS == platformWindows {
		out, err := exec.Command("getmac", "/fo", "csv", "/v").CombinedOutput()
		if err != nil {
			die(err.Error(), "failed to execute getmac to the transport name identifier")
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, iface) {
				elements := strings.Split(line, ",")
				if len(elements) != 4 {
					die("unexpected length", strconv.Itoa(len(elements)))
				}
				iface = strings.TrimSpace(strings.Replace(elements[3], "\\Device\\Tcpip_", "\\Device\\NPF_", 1))
				// remove string literals from start and end of string
				iface = string([]rune(iface)[1 : len(iface)-1])
				log.Println("got interface transport identifier", iface)
				break
			}
		}
	}

	// prepare arguments
	args := []string{
		"capture",
		"-iface", iface,
		"-out", outDir,
		"-fileStorage=files",
		"-config=" + filepath.Join("/usr", "local", "etc", "netcap", "livecapture.conf"),
		"-noprompt",
		"-http-shutdown=true",
	}

	if snapL > 0 {
		args = append(args, "-snaplen="+strconv.Itoa(snapL))
	}

	// check if a custom bpf was provided as property
	if bpf, ok := lt.Values["bpf"]; ok {
		if bpf != "" {
			args = append(args, "-bpf="+bpf)
		}
	}

	log.Println("args:", args)

	cmd := exec.Command(maltego.ExecutablePath, args...)
	// TODO: on windows this will lead to a blocking transform - verify if this is still the case with writing into buffer
	// add env var "NC_MALTEGO_DEBUG" for maltego debug mode
	// and only attach in debug mode
	var buf bytes.Buffer
	cmd.Stderr = io.MultiWriter(&buf)

	err := cmd.Start()
	if err != nil {
		die(err.Error(), "failed to start capture process")
	}

	log.Println("> PID", cmd.Process.Pid)

	// wait for command in background and crash with error if it returns
	go func() {
		err := cmd.Wait()
		if err != nil {
			die(err.Error(), buf.String())
		}
	}()

	time.Sleep(5 * time.Second)
	returnCaptureProcessEntity(cmd.Process.Pid, outDir, lt.Value)

	log.Println("exit 0", buf.String())
	os.Exit(0)
}

func getPathLiveCaptureOutDir(iface string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Join(home, iface+".net")
}

func returnCaptureProcessEntity(pid int, path string, iface string) {
	pidStr := strconv.Itoa(pid)

	// generate maltego transform
	trx := maltego.Transform{}

	name := "Capture Process" + "\nPID: " + pidStr
	ent := trx.AddEntityWithPath("netcap.CaptureProcess", name, path)

	ent.AddProperty("pid", "PID", maltego.Strict, pidStr)

	ent.AddProperty("iface", "Interface", maltego.Strict, iface)

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
