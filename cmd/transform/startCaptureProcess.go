/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	"bytes"
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/dreadl0ck/maltego"
)

func startCaptureProcess() {
	var (
		lt    = maltego.ParseLocalArguments(os.Args[3:])
		snapL int
	)
	log.Println("capture on interface:", lt.Value)

	// check if a custom snaplen was provided as property
	if snaplen, ok := lt.Values["snaplen"]; ok {
		if snaplen != "" {
			n, err := strconv.Atoi(snaplen)
			if err != nil {
				maltego.Die(err.Error(), "invalid snaplen provided")
			}

			if n <= 0 {
				maltego.Die("invalid snaplen", "snaplen must not be <= 0")
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
			maltego.Die(err.Error(), "failed to execute getmac to the transport name identifier")
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, iface) {
				elements := strings.Split(line, ",")
				if len(elements) != 4 {
					maltego.Die("unexpected length", strconv.Itoa(len(elements)))
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
		"-conns",
		"-debug",
		//"-config=" + filepath.Join("/usr", "local", "etc", "netcap", "livecapture.conf"),
		"-noprompt",
		"-workers=1",
		"-http-shutdown=true",
	}

	if snapL > 0 {
		args = append(args, "-snaplen="+strconv.Itoa(snapL))
	}

	// check if a custom bpf was provided as property
	if bpf, ok := lt.Values["bpf"]; ok {
		if bpf != "" {
			args = append(args, "-bpf=\""+bpf+"\"")
		}
	}

	// check if a custom bpf was provided as property
	if bpf, ok := lt.Values["bpf"]; ok {
		if bpf != "" {
			args = append(args, "-bpf=\""+bpf+"\"")
		}
	}

	// check if a custom bpf was provided as property
	if bpf, ok := lt.Values["bpf"]; ok {
		if bpf != "" {
			args = append(args, "-bpf=\""+bpf+"\"")
		}
	}

	log.Println("args:", args)

	var buf bytes.Buffer

	// TODO: invoke on the shell VS start within this process?
	cmd := exec.Command(netmaltego.ExecutablePath, args...)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	cmd.Stdout = os.Stderr

	err := cmd.Start()
	if err != nil {
		maltego.Die(err.Error(), "failed to start capture process")
	}

	log.Println("> PID", cmd.Process.Pid)

	defer func() {
		if errPanic := recover(); err != nil {
			maltego.Die(errPanic.(error).Error(), "process panic")
		}
	}()

	err = cmd.Wait()
	if err != nil {
		maltego.Die(err.Error(), "error while waiting for capture process:\n"+buf.String())
	}

	trx := &maltego.Transform{}
	trx.AddUIMessage("completed", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())

	os.Exit(0)
}

func getPathLiveCaptureOutDir(iface string) string {
	if iface == "" {
		maltego.Die("empty interface string received", "getPathLiveCaptureOutDir")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		maltego.Die(err.Error(), "failed to get user homedir")
	}
	return filepath.Join(home, iface+".net")
}
