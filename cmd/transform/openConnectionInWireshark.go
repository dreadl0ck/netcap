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
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/defaults"
)

var (
	wireshark = "wireshark"
	tcpdump   = "tcpdump"
)

func init() {
	if runtime.GOOS == platformWindows {
		tcpdump = "tcpdump.exe"
		wireshark = "C:\\Program Files\\Wireshark\\Wireshark.exe"
	}
}

// TODO: refactor this method, last three params are only used for the software transform atm
func makeOutFilePath(in, bpf string, lt maltego.LocalTransform, flows bool, bpfSummary string) (name string, exists bool) {
	log.Println("os.Environment:", os.Environ())

	// output the files to an directory inside the netcap folder
	outPath := filepath.Join(in+".net", "extractedStreams")
	_ = os.Mkdir(outPath, defaults.DirectoryPermission)

	// the base of the input string is the pcap filename, strip the extensions
	fileName := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(in), ".pcap"),
		".pcapng",
	)

	// join the out path with the new file name
	if flows {
		// group multiple flows so the filename does not grow too long
		name = filepath.Join(
			outPath,
			fileName+"-software-"+lt.Values["product"]+"-"+bpfSummary+".pcap",
		)
	} else {
		// replace all whitespace in the bpf with dashes
		name = filepath.Join(
			outPath,
			fileName+"-"+strings.ReplaceAll(bpf, " ", "-")+".pcap",
		)
	}

	_, err := os.Stat(name)
	if err == nil {
		// no error, file exists
		return name, true
	}
	return name, false
}

func findExecutable(name string, ignoreErr bool) string {

	var paths []string

	path, err := exec.LookPath(name)
	if err != nil {

		paths = append(paths, "$PATH")

		// on linux and macOS: search the binary in /usr/local/bin
		if runtime.GOOS == platformDarwin || runtime.GOOS == platformLinux {

			// search ida binary in /usr/local/bin/ida, as it needs the shared objects in the same folder as the binary
			if name == "ida64" {
				name = "ida/ida64"
			}

			p := filepath.Join("/usr", "local", "bin", name)
			path, err = exec.LookPath(p)
			if err != nil {

				paths = append(paths, p)
				p = filepath.Join("/snap", "bin", name)

				path, err = exec.LookPath(p)
				if err != nil {
					paths = append(paths, p)
					if !ignoreErr {
						maltego.Die(name + " executable not found", "paths tried:\n"+strings.Join(paths, "\n")+"\n$PATH = "+os.Getenv("PATH"))
					}
				}
			}
		}
	}

	return path
}

func openConnectionInWireshark() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args[3:])
		trx             = &maltego.Transform{}
		bpf             = makeConnectionBPF(lt)
		in              = strings.TrimSuffix(filepath.Dir(strings.TrimPrefix(lt.Values["path"], "file://")), ".net")
		outFile, exists = makeOutFilePath(in, bpf, lt, false, "")
		args            = []string{"-r", in, "-w", outFile, bpf}
	)

	if !exists {
		log.Println(tcpdump, args)

		out, err := exec.Command(findExecutable(tcpdump, false), args...).CombinedOutput()
		if err != nil {
			maltego.Die(err.Error(), "open file failed:\n"+string(out))
		}

		log.Println(string(out))
	}

	log.Println(wireshark, outFile)

	out, err := exec.Command(findExecutable(wireshark, false), outFile).CombinedOutput()
	if err != nil {
		maltego.Die(err.Error(), "open file failed:\n"+string(out))
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

// creates a bpf to filter for traffic of a single connection
// defined by two hosts and two ports
// eg: "(host 192.168.1.14 and port 56988) and (host 224.0.0.252 and port 5355)"
func makeConnectionBPF(lt maltego.LocalTransform) string {
	var b strings.Builder

	b.WriteString("(host ")
	b.WriteString(lt.Values["srcip"])
	b.WriteString(" and port ")
	b.WriteString(lt.Values["srcport"])
	b.WriteString(") and (host ")
	b.WriteString(lt.Values["dstip"])
	b.WriteString(" and port ")
	b.WriteString(lt.Values["dstport"])
	b.WriteString(")")

	return b.String()
}
