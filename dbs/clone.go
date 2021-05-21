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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// CloneDBs will clone the data bases initially from the public git repository
// TODO: add windows support
func CloneDBs(force bool) {

	if !force {

		// check if git lfs is installed
		err := exec.Command("git", "lfs", "env").Run()
		if err != nil {
			// inform user
			if !utils.Confirm(`Please ensure the git LTS extension is installed on your system.

Apt/deb: sudo apt-get install git-lfs
Yum/rpm: sudo yum install git-lfs
MacOS: brew install git-lfs

Proceed?`) {
				fmt.Println("aborted.")
				return
			}
		}

		// fetch expected size from github repo
		resp, err := http.Get("https://raw.githubusercontent.com/dreadl0ck/netcap-dbs/main/size")
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		// read http body
		size, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		// check status
		if resp.StatusCode != http.StatusOK {
			log.Fatal("got an unexpected status from github while trying to fetch expected database size: ", resp.Status)
		}

		// display the expected db size to the user and ask for confirmation
		if !utils.Confirm("This will fetch " + string(size) + " of data. Proceed?") {
			fmt.Println("aborted.")
			return
		}
	}

	// check if database root path exists already
	if _, err := os.Stat(resolvers.ConfigRootPath); err == nil {

		// read directory
		files, errFiles := ioutil.ReadDir(resolvers.ConfigRootPath)
		if errFiles != nil {
			log.Fatal("failed to read directory: ", errFiles)
		}

		// there must be files present to assume that it can be updated
		if len(files) > 0 {
			fmt.Println("clone: database directory exists. checking for updates instead...")
			UpdateDBs()
			return
		}
	} else {

		// it does not - create it
		errMkdir := os.MkdirAll(resolvers.ConfigRootPath, defaults.DirectoryPermission)
		if errMkdir != nil {
			log.Println("failed to create config root path: ", errMkdir)
		}
	}

	// move into ConfigRootPath
	err := os.Chdir(resolvers.ConfigRootPath)
	if err != nil {
		log.Fatal("failed to move into config root path: ", err)
	}

	// Skip smudge during cloning, we will fetch LFS resources in a second step.
	// This is a workaround due a bug described here: https://github.com/git-lfs/git-lfs/issues/911
	// It happens during cloning an LFS repository in an alpine container exclusively, cloning on macOS and debian worked flawlessly.
	// Downloading the LFS in a second step is apparently also faster.
	out, err := exec.Command("git", "lfs", "install", "--skip-smudge").CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		log.Fatal("failed to disable lfs smudge: ", err)
	}

	// clone repo
	// go-git does not yet support LFS... we need to shell out
	cmd := exec.Command("git", "clone", "https://github.com/dreadl0ck/netcap-dbs.git", resolvers.ConfigRootPath)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		log.Fatal("failed to clone netcap-dbs repo: ", err)
	}

	fmt.Println("cloned netcap-dbs repository to", resolvers.ConfigRootPath)

	// Fetch all the binary files in the new clone
	cmd = exec.Command("git", "lfs", "pull")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		log.Fatal("failed to pull files from git lfs: ", err)
	}

	// Reinstate smudge
	err = exec.Command("git", "lfs", "install", "--force").Run()
	if err != nil {
		log.Fatal("failed to reinstate smudge: ", err)
	}

	fmt.Println("done! Downloaded databases to", resolvers.ConfigRootPath)
}
