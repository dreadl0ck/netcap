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
	"github.com/dreadl0ck/netcap/utils"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dustin/go-humanize"
	"github.com/evilsocket/islazy/zip"
)

// A simple hook function that provides the option to modify the fetched data
type datasourceHook func(in string, d *datasource, base string) error

type datasource struct {
	url  string
	name string
	hook datasourceHook
}

func makeSource(url, name string, hook datasourceHook) *datasource {
	// if no name provided: use base
	if name == "" {
		name = filepath.Base(utils.StripQueryString(url))
	}
	return &datasource{
		url:  url,
		name: name,
		hook: hook,
	}
}

// NVD database starts at year 2002
var nvdStartYear = 2002

/*
 * Sources
 */

var sources = []*datasource{
	// TODO: implement generation
	//makeSource("https://raw.githubusercontent.com/0x4D31/hassh-utils/master/hasshdb", "hasshdb.txt", moveToDbs), // hasshdb.json
	//makeSource("https://raw.githubusercontent.com/karottc/fingerbank/master/upstream/startup/fingerprints.csv", "", moveToDbs), // dhcp-fingerprints.json
	//makeSource("https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json", "", moveToDbs), // cmsdb.json

	// this clones the latest versions until the generation is implemented
	makeSource("https://raw.githubusercontent.com/dreadl0ck/netcap-dbs/main/dbs/hasshdb.json", "", moveToDbs),
	makeSource("https://raw.githubusercontent.com/dreadl0ck/netcap-dbs/main/dbs/dhcp-fingerprints.json", "", moveToDbs),
	makeSource("https://raw.githubusercontent.com/dreadl0ck/netcap-dbs/main/dbs/cmsdb.json", "", moveToDbs),

	makeSource("http://s3.amazonaws.com/alexa-static/top-1m.csv.zip", "domain-whitelist.csv", unzipAndMoveToDbs),
	makeSource("https://raw.githubusercontent.com/tobie/ua-parser/master/regexes.yaml", "", moveToDbs),

	// TODO: manage custom netcap probes separately and merge
	makeSource("https://svn.nmap.org/nmap/nmap-service-probes", "", moveToDbs),
	makeSource("https://macaddress.io/database/macaddress.io-db.json", "", moveToDbs),
	makeSource("https://ja3er.com/getAllHashesJson", "ja3erDB.json", moveToDbs),
	makeSource("https://ja3er.com/getAllUasJson", "ja3UserAgents.json", moveToDbs),
	makeSource("https://raw.githubusercontent.com/dreadl0ck/netcap-dbs/main/dbs/ja_3_3s.json", "", moveToDbs),
	makeSource("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv", "", moveToDbs),
	makeSource("https://raw.githubusercontent.com/trisulnsm/trisul-scripts/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json", "", moveToDbs),
	makeSource("https://web.archive.org/web/20191227182527if_/https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz", "", untarAndMoveGeoliteToBuildDbs),
	makeSource("https://web.archive.org/web/20191227182209if_/https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz", "", untarAndMoveGeoliteToBuildDbs),
	makeSource("", "nvd.bleve", downloadAndIndexNVD),
	makeSource("https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv", "", downloadAndIndexExploitDB),
}

/*
 * Datasource Hooks
 */

func unzipAndMoveToDbs(in string, d *datasource, base string) error {
	filenames, err := zip.Unzip(in, filepath.Join(base, "build"))
	if err != nil {
		return err
	}

	if len(filenames) > 1 {
		log.Fatal("archive contains more than one file, not sure what to do")
	}

	f := filenames[0]

	return os.Rename(
		filepath.Join(base, "build", filepath.Base(f)),
		filepath.Join(base, "dbs", d.name),
	)
}

func downloadAndIndexNVD(_ string, _ *datasource, base string) error {
	for _, year := range yearRange(nvdStartYear, time.Now().Year()) {
		s := makeSource(fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz", year), "", nil)
		fetchResource(s, filepath.Join(base, "build", s.name))
	}
	IndexData("nvd", filepath.Join(base, "dbs"), filepath.Join(base, "build"), nvdStartYear, false)
	return nil
}

func downloadAndIndexExploitDB(_ string, _ *datasource, base string) error {
	IndexData("exploit-db", filepath.Join(base, "dbs"), filepath.Join(base, "build"), 0, false)
	return nil
}

func moveToDbs(in string, d *datasource, base string) error {
	return os.Rename(in, filepath.Join(base, "dbs", d.name))
}

// unpack compressed tarballs and move geolite db files to the build/dbs directory
func untarAndMoveGeoliteToBuildDbs(in string, d *datasource, base string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil {
			log.Fatal(errClose)
		}
	}()

	name, err := unpackTarball(f, filepath.Join(base, "build"))
	fmt.Println("unpacked", name)

	// extract *.mmdb files
	files, err := filepath.Glob(filepath.Join(base, "build", name, "*.mmdb"))
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fmt.Println("extracting file", file)
		err = os.Rename(
			filepath.Join(base, "build", name, filepath.Base(file)),
			filepath.Join(base, "dbs", filepath.Base(file)),
		)
		if err != nil {
			log.Fatal(err)
		}
	}

	return err
}

// unpack compressed tarballs and move geolite db files to the dbs directory
func untarAndMoveGeoliteToDbs(in string, d *datasource, base string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil {
			log.Fatal(errClose)
		}
	}()

	name, err := unpackTarball(f, base)
	fmt.Println("unpacked", name)

	// extract *.mmdb files
	files, err := filepath.Glob(filepath.Join(base, name, "*.mmdb"))
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		out := filepath.Join(base, "dbs", filepath.Base(file))
		fmt.Println("extracting file", filepath.Base(file), "to", out)
		err = os.Rename(
			filepath.Join(base, name, filepath.Base(file)),
			out,
		)
		if err != nil {
			log.Fatal(err)
		}
	}

	return err
}

/*
 * Main
 */

var (
	numBytesFetched   uint64
	numBytesFetchedMu sync.Mutex
)

// GenerateDBs allows to fetch the databases from their initial sources and generate the preprocessed form that netcap uses
func GenerateDBs(nvdIndexStartYear int) {

	var (
		base  = "netcap-dbs-generated"
		_     = os.MkdirAll(filepath.Join(base, "build"), defaults.DirectoryPermission)
		_     = os.MkdirAll(filepath.Join(base, "dbs"), defaults.DirectoryPermission)
		wg    sync.WaitGroup
		start = time.Now()
		total int
	)

	if nvdIndexStartYear != 0 {
		nvdStartYear = nvdIndexStartYear
	}

	for _, s := range sources {
		total++
		wg.Add(1)
		go processSource(s, base, &wg)
	}

	time.Sleep(1 * time.Second)
	fmt.Println("waiting for downloads to complete...")
	wg.Wait()

	// shell out to print a directory tree
	out, err := exec.Command("tree", base).CombinedOutput()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(out))

	// save the total size into a file named "size"
	// will be used to ask the user for confirmation
	// prior to cloning the repo via the netcap toolchain
	saveTotalDatabaseSize(base)

	fmt.Println("fetched", total, "sources ("+humanize.Bytes(numBytesFetched)+")", "in", time.Since(start))

	gitLfsPrune()
}

func processSource(s *datasource, base string, wg *sync.WaitGroup) {

	outFilePath := filepath.Join(base, "build", s.name)

	// fetch via HTTP GET from single remote source if provided
	// if multiple sources need to be fetched, the logic can be implemented in the hook
	fetchResource(s, outFilePath)

	// run hook
	if s.hook != nil {
		err := s.hook(outFilePath, s, base)
		if err != nil {
			log.Println("hook for", s.name, "failed with error", err)
		}
	}

	wg.Done()
}

// fetchResource will attempt to download a resource
// TODO: return error instead of fataling on errors, a single failed component should not make the entire process fail.
func fetchResource(s *datasource, outFilePath string) {
	if s.url != "" {

		fmt.Println("fetching", s.name, "from", utils.StripQueryString(s.url))

		var (
			numRetries int
			maxRetries = 2
		)

	retry:
		// execute GET request
		resp, err := http.Get(s.url)
		if err != nil {
			numRetries++
			if numRetries <= maxRetries {
				fmt.Println("failed to retrieve data from", s, "will try again (", numRetries, "/", maxRetries, ")")
				goto retry
			}
			log.Fatal("failed to retrieve data from", s)
		}

		// check status
		if resp.StatusCode != http.StatusOK {
			log.Fatal("failed to retrieve data from", s, resp.Status)
		}

		// read body data
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal("failed to read body data from", s, " error: ", err)
		}
		defer resp.Body.Close()

		numBytesFetchedMu.Lock()
		numBytesFetched += uint64(len(data))
		numBytesFetchedMu.Unlock()

		// create output file in build folder
		f, err := os.Create(outFilePath)
		if err != nil {
			log.Fatal("failed to create file in build folder", s, " error: ", err)
		}

		// write data into file
		_, err = f.Write(data)
		if err != nil {
			log.Fatal("failed to write data to file in build folder", s, " error: ", err)
		}

		// close the file
		err = f.Close()
		if err != nil {
			log.Fatal("failed to close file in build folder", s, " error: ", err)
		}
	}
}

// webTechnologies models different web technologies
// TODO: automate generation of cmsdb.json from the technologies.json file
type webTechnologies struct {
	Schema     string `json:"$schema"`
	Categories struct {
		Num1 struct {
			Name     string `json:"name"`
			Priority int    `json:"priority"`
		} `json:"1"`
	} `json:"categories"`
	Technologies struct {
		OneCBitrix struct {
			Cats        []int  `json:"cats"`
			Description string `json:"description"`
			Headers     struct {
				SetCookie   string `json:"Set-Cookie"`
				XPoweredCMS string `json:"X-Powered-CMS"`
			} `json:"headers"`
			HTML    string `json:"html"`
			Icon    string `json:"icon"`
			Implies string `json:"implies"`
			Scripts string `json:"scripts"`
			Website string `json:"website"`
		} `json:"1C-Bitrix"`
	} `json:"technologies"`
}
