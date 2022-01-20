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
	"strings"

	"github.com/dreadl0ck/maltego"
)

func openDeviceTrafficInWireshark() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		in              = strings.TrimSuffix(filepath.Dir(strings.TrimPrefix(lt.Values["path"], "file://")), ".net")
		bpf             = makeDeviceBPF(lt)
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

// creates a bpf to filter for traffic of a mac address
// eg: "ether host 00:22:15:63:c9:5a"
func makeDeviceBPF(lt maltego.LocalTransform) string {
	var b strings.Builder

	b.WriteString("ether host ")
	b.WriteString(lt.Values["mac"])

	return b.String()
}
