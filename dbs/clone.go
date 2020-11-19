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

package dbs

import (
	"fmt"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/zip"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// TODO: display expected size before retrieval and prompt for confirmation
// TODO: add windows support
func CloneDBs() {

	// TODO: add force flag to allow automation
	if !utils.Confirm(`Please ensure the git LTS extension is installed on your system.

Apt/deb: sudo apt-get install git-lfs
Yum/rpm: sudo yum install git-lfs
MacOS: brew install git-lfs

Proceed?`) {
		return
	}

	// check if database root path exists already
	if _, err := os.Stat(resolvers.ConfigRootPath); err == nil {
		log.Fatal("database root path: ", resolvers.ConfigRootPath, " exists already")
	}

	// it does not - create it
	_ = os.MkdirAll(resolvers.ConfigRootPath, defaults.DirectoryPermission)

	// clone repo
	// go-git does not yet support LFS... we need to shell out
	//_, err := git.PlainClone(resolvers.ConfigRootPath, false, &git.CloneOptions{
	//	URL:      "https://github.com/dreadl0ck/netcap-dbs.git",
	//	Progress: os.Stdout,
	//})
	//if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
	//	log.Fatal("failed to clone netcap-dbs repository:", err)
	//}
	cmd := exec.Command("git", "clone", "https://github.com/dreadl0ck/netcap-dbs.git", resolvers.ConfigRootPath)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		log.Fatal("failed to clone netcap-dbs repo: ", err)
	}

	fmt.Println("cloned netcap-dbs repository to", resolvers.ConfigRootPath)

	// decompress bleve stores
	files, err := ioutil.ReadDir(resolvers.DataBaseFolderPath)
	if err != nil {
		log.Fatal("failed to read dir: ", resolvers.DataBaseFolderPath, err)
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == ".zip" {
			fmt.Println("decompressing", f.Name())
			_, err = zip.Unzip(
				filepath.Join(resolvers.DataBaseFolderPath, f.Name()),
				resolvers.DataBaseFolderPath,
			)
			if err != nil {
				log.Fatal("failed to unzip: ", f.Name(), " error: ", err)
			}
		}
	}

	fmt.Println("done! Downloaded databases to", resolvers.ConfigRootPath)
}
