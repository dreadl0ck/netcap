package util

import (
	"fmt"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/evilsocket/islazy/zip"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// TODO: display expected size before retrieval and prompt for confirmation
func cloneDBs() {

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