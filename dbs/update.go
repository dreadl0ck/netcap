/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package dbs

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/cryptoutils"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// UpdateDBs will update the databases on disk by pulling from the public github repository
func UpdateDBs() {

	// check if database root path exists already
	if _, err := os.Stat(resolvers.ConfigRootPath); err != nil {
		log.Fatal("database root path: ", resolvers.ConfigRootPath, " does not exist")
	}

	var (
		pathASN  = filepath.Join(resolvers.DataBaseFolderPath, "GeoLite2-ASN.mmdb")
		pathCity = filepath.Join(resolvers.DataBaseFolderPath, "GeoLite2-City.mmdb")
	)

	// backup the recent versions of the GeoLite databases
	// so they wont get overwritten by the outdated ones from upstream
	asnDB, err := ioutil.ReadFile(pathASN)
	if err != nil {
		log.Fatal(err)
	}

	cityDB, err := ioutil.ReadFile(pathCity)
	if err != nil {
		log.Fatal(err)
	}

	var (
		asnHash  = hex.EncodeToString(cryptoutils.MD5Data(asnDB))
		cityHash = hex.EncodeToString(cryptoutils.MD5Data(cityDB))
	)

	if asnHash != "17eea01c955ada90ad922c2c95455515" {
		utils.CopyFile(pathASN, "/tmp")
	}
	if cityHash != "10b66842fd51336ae7c4f34c058deb46" {
		utils.CopyFile(pathCity, "/tmp")
	}

	err = os.Chdir(resolvers.ConfigRootPath)
	if err != nil {
		log.Fatal("could not move into database directory: ", err)
	}

	out, err := exec.Command("git", "fetch", "origin").CombinedOutput()
	if err != nil {
		log.Fatal("failed to run git fetch: ", err)
	}
	if len(out) == 0 {
		fmt.Println("Already up to date.")
		return
	}

	cmd := exec.Command("git", "pull")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		log.Fatal("failed to pull netcap-dbs repo: ", err)
	}

	fmt.Println("pulled netcap-dbs repository")

	// restore geolite dbs
	if asnHash != "17eea01c955ada90ad922c2c95455515" {
		utils.CopyFile(filepath.Join("/tmp", filepath.Base(pathASN)), pathASN)
	}
	if cityHash != "10b66842fd51336ae7c4f34c058deb46" {
		utils.CopyFile(filepath.Join("/tmp", filepath.Base(pathCity)), pathCity)
	}

	fmt.Println("done! Updated databases to", resolvers.ConfigRootPath)
}
