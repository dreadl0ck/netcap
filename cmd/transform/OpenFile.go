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
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/dreadl0ck/netcap/maltego"
)

func openFile() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.Transform{}
		openCommandName = os.Getenv(envOpenFileCommand)
		args            []string
	)

	// if no command has been supplied via environment variable
	// then default to:
	// - open for macOS
	// - gio open for linux
	if openCommandName == "" {
		if runtime.GOOS == platformDarwin {
			openCommandName = defaultOpenCommand
		} else { // linux
			openCommandName = defaultOpenCommandLinux
			args = append(args, "open")
		}
	}

	loc := lt.Values["location"]

	// the open tool uses the file extension to decide which program to pass the file to
	// if there is an extension for known executable formats - abort
	ext := filepath.Ext(loc)
	log.Println("file extension", ext)

	if ext == ".exe" || ext == ".bin" {
		log.Println("detected known executable file extension - aborting to prevent accidental execution!")
		trx.AddUIMessage("completed!", maltego.UIMessageInform)
		fmt.Println(trx.ReturnOutput())

		return
	}

	// if there is no extension, use content type detection to determine if its an executable
	// TODO: improve and test content type check and executable file detection
	log.Println("open path for determining content type:", loc)

	f, err := os.OpenFile(lt.Values["location"], os.O_RDONLY, outDirPermission)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	buf := make([]byte, 512)

	_, err = io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		log.Fatal(err)
	}

	// check if file is executable to prevent accidental execution
	cType := http.DetectContentType(buf)
	log.Println("cType:", cType)

	stat, err := os.Stat(lt.Values["location"])
	if err != nil {
		log.Fatal(err)
	}

	if cType == "application/octet-stream" && isExecAny(stat.Mode()) {
		log.Println("detected executable file - aborting to prevent accidental execution!")
		trx.AddUIMessage("completed!", maltego.UIMessageInform)
		fmt.Println(trx.ReturnOutput())

		return
	}

	args = append(args, loc)
	log.Println("final command for opening files:", openCommandName, args)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

func isExecAny(mode os.FileMode) bool {
	return mode&0o111 != 0
}
