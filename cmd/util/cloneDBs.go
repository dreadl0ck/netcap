package util

import (
	"errors"
	"fmt"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/evilsocket/islazy/zip"
	"io/ioutil"
	"log"
	"os"
	"github.com/go-git/go-git/v5"
	"path/filepath"
	"strings"
)

// TODO: display expected size before retrieval and prompt for confirmation
func cloneDBs() {

	// check if database root path exists already
	if _, err := os.Stat(resolvers.ConfigRootPath); err == nil {
		log.Fatal("database root path", resolvers.ConfigRootPath, "exists already")
	}

	// it does not - create it
	_ = os.MkdirAll(resolvers.ConfigRootPath, defaults.DirectoryPermission)

	// change into dir
	//err := os.Chdir(resolvers.DataBaseRootPath)
	//if err != nil {
	//	log.Fatal("failed to move into", resolvers.DataBaseRootPath, err)
	//}

	// clone repo
	_, err := git.PlainClone(resolvers.ConfigRootPath, false, &git.CloneOptions{
		URL:      "https://github.com/dreadl0ck/netcap-dbs.git",
		Progress: os.Stdout,
	})
	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		log.Fatal("failed to clone netcap-dbs repository:", err)
	}

	fmt.Println("cloned netcap-dbs repository to", resolvers.ConfigRootPath)

	// rename? TODO
	//err = os.Rename(filepath.Join(dir, "netcap-dbs"), filepath.Join(dir, "netcap"))
	//if err != nil {
	//	log.Fatal("failed to rename", dir, err)
	//}

	// decompress bleve stores
	files, err := ioutil.ReadDir(resolvers.DataBaseFolderPath)
	if err != nil {
		log.Fatal("failed to read dir", resolvers.DataBaseFolderPath, err)
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == ".zip" {
			fmt.Println("decompressing", f.Name())
			_, err = zip.Unzip(
				filepath.Join(resolvers.DataBaseFolderPath, f.Name()),
				strings.TrimSuffix(
					filepath.Join(resolvers.DataBaseFolderPath, f.Name()),
					".zip",
				),
			)
			if err != nil {
				log.Fatal("failed to unzip", f.Name(), err)
			}
		}
	}

	fmt.Println("done! Downloaded databases to", resolvers.ConfigRootPath)
}