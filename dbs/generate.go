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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/utils"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/archive"
	"github.com/dreadl0ck/netcap/internal/httputil"
)

// defaultSourceTimeout caps the total wall-clock time spent fetching a single
// data source (including retries and backoff). It exists so a blackholed
// upstream like ja4db.com cannot keep the rebuild stalled for minutes per
// run. The default mirrors the slowest known good source on a healthy network
// with headroom. Overridable via the NC_DBS_SOURCE_TIMEOUT environment
// variable (Go duration syntax, e.g. "90s" or "2m").
const defaultSourceTimeout = 60 * time.Second

// sourceTimeout returns the per-source overall timeout, honouring the
// NC_DBS_SOURCE_TIMEOUT env override. Invalid values fall back to the
// default.
func sourceTimeout() time.Duration {
	if v := os.Getenv("NC_DBS_SOURCE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultSourceTimeout
}

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

	// JA4+ fingerprint database from FoxIO
	makeSource("https://ja4db.com/api/download/", "ja4db.json", moveToDbs),

	makeSource("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv", "", moveToDbs),
	makeSource("https://web.archive.org/web/20191227182527if_/https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz", "", untarAndMoveGeoliteToBuildDbs),
	makeSource("https://web.archive.org/web/20191227182209if_/https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz", "", untarAndMoveGeoliteToBuildDbs),

	makeSource("", "nvd.bleve", downloadAndIndexNVD),
	makeSource("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", "", downloadAndIndexExploitDB),
}

/*
 * Datasource Hooks
 */

func unzipAndMoveToDbs(in string, d *datasource, base string) error {
	filenames, err := archive.ExtractZip(in, filepath.Join(base, "build"))
	if err != nil {
		return err
	}

	if len(filenames) > 1 {
		log.Printf("WARNING: archive %s contains more than one file, using first file only", d.name)
	}

	f := filenames[0]

	return os.Rename(
		filepath.Join(base, "build", filepath.Base(f)),
		filepath.Join(base, "dbs", d.name),
	)
}

func downloadAndIndexNVD(_ string, _ *datasource, base string) error {
	
	for _, year := range yearRange(nvdStartYear, time.Now().Year()) {

		s := makeSource(fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%s.json.gz", year), "", nil)
    err := fetchResource(s, filepath.Join(base, "build", s.name))
    if err != nil {
			log.Printf("ERROR: failed to fetch NVD data for year %s: %v", year, err)
			continue
		}
	}
	
	return nil
}

func downloadAndIndexExploitDB(_ string, _ *datasource, base string) error {
	// Clone the exploitdb repository to get the actual exploit files
	exploitdbPath := filepath.Join(base, "dbs", "exploitdb")

	// Always clone fresh to get the latest exploits
	if _, err := os.Stat(exploitdbPath); err == nil {
		fmt.Println("Removing existing exploitdb to clone fresh...")
		if err := os.RemoveAll(exploitdbPath); err != nil {
			log.Printf("Warning: Failed to remove existing exploitdb: %v", err)
		}
	}

	fmt.Println("Cloning exploitdb repository (this may take a few minutes)...")

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(exploitdbPath), defaults.DirectoryPermission); err != nil {
		log.Printf("Warning: Failed to create parent directory for exploitdb: %v", err)
	} else {
		// Use shallow clone with depth 1 to save space and time
		cmd := exec.Command("git", "clone", "--depth", "1",
			"https://gitlab.com/exploit-database/exploitdb.git",
			exploitdbPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Failed to clone exploitdb repository: %v", err)
			log.Println("Exploit POC files will not be available, but metadata indexing will continue")
		} else {
			fmt.Printf("Successfully cloned exploitdb to %s\n", exploitdbPath)

			// Remove .git directory to save space in the tarball
			gitDir := filepath.Join(exploitdbPath, ".git")
			if err := os.RemoveAll(gitDir); err != nil {
				log.Printf("Warning: Failed to remove .git directory: %v", err)
			} else {
				fmt.Println("Removed .git directory to save space")
			}
		}
	}

	// Index the exploit metadata
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
			log.Printf("WARNING: failed to close file %s: %v", in, errClose)
		}
	}()

	name, err := unpackTarball(f, filepath.Join(base, "build"))
	if err != nil {
		return fmt.Errorf("failed to unpack tarball: %v", err)
	}
	fmt.Println("unpacked", name)

	// extract *.mmdb files
	files, err := filepath.Glob(filepath.Join(base, "build", name, "*.mmdb"))
	if err != nil {
		return fmt.Errorf("failed to glob for mmdb files: %v", err)
	}

	for _, file := range files {
		fmt.Println("extracting file", file)
		err = os.Rename(
			filepath.Join(base, "build", name, filepath.Base(file)),
			filepath.Join(base, "dbs", filepath.Base(file)),
		)
		if err != nil {
			return fmt.Errorf("failed to move file %s: %v", file, err)
		}
	}

	return nil
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
			log.Printf("WARNING: failed to close file %s: %v", in, errClose)
		}
	}()

	name, err := unpackTarball(f, base)
	if err != nil {
		return fmt.Errorf("failed to unpack tarball: %v", err)
	}
	fmt.Println("unpacked", name)

	// extract *.mmdb files
	files, err := filepath.Glob(filepath.Join(base, name, "*.mmdb"))
	if err != nil {
		return fmt.Errorf("failed to glob for mmdb files: %v", err)
	}

	for _, file := range files {
		out := filepath.Join(base, "dbs", filepath.Base(file))
		fmt.Println("extracting file", filepath.Base(file), "to", out)
		err = os.Rename(
			filepath.Join(base, name, filepath.Base(file)),
			out,
		)
		if err != nil {
			return fmt.Errorf("failed to move file %s to %s: %v", file, out, err)
		}
	}

	return nil
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
		successCount int
		failureCount int
		mu    sync.Mutex // protect counters
	)

	if nvdIndexStartYear != 0 {
		nvdStartYear = nvdIndexStartYear
	}

	for _, s := range sources {
		total++
		wg.Add(1)
		go func(source *datasource) {
			defer wg.Done()
			
			success := processSource(source, base)
			mu.Lock()
			if success {
				successCount++
			} else {
				failureCount++
			}
			mu.Unlock()
		}(s)
	}

	time.Sleep(1 * time.Second)
	fmt.Println("waiting for downloads to complete...")
	wg.Wait()

	// Print summary
	fmt.Printf("\n=== Download Summary ===\n")
	fmt.Printf("Total sources: %d\n", total)
	fmt.Printf("Successful: %d\n", successCount)
	fmt.Printf("Failed: %d\n", failureCount)
	fmt.Printf("Total bytes fetched: %s\n", humanize.Bytes(numBytesFetched))
	fmt.Printf("Duration: %v\n", time.Since(start))

	if failureCount > 0 {
		log.Printf("WARNING: %d out of %d data sources failed to download. Check logs above for details.", failureCount, total)
	}

	// shell out to print a directory tree
	out, err := exec.Command("tree", base).CombinedOutput()
	if err != nil {
		fmt.Printf("Unable to display directory tree: %v\n", err)
	} else {
		fmt.Println(string(out))
	}

	// save the total size into a file named "size"
	// will be used to ask the user for confirmation
	// prior to cloning the repo via the netcap toolchain
	saveTotalDatabaseSize(base)

  fmt.Printf("Operation completed: fetched %d sources successfully ("+humanize.Bytes(numBytesFetched)+") in %v\n", successCount, time.Since(start))
  
	// Verify exploitdb folder is present
	exploitdbPath := filepath.Join(base, "dbs", "exploitdb")
	if stat, err := os.Stat(exploitdbPath); err == nil && stat.IsDir() {
		// Count files in exploitdb to give user feedback
		var fileCount int
		_ = filepath.Walk(exploitdbPath, func(_ string, info os.FileInfo, _ error) error {
			if info != nil && !info.IsDir() {
				fileCount++
			}
			return nil
		})
		fmt.Printf("✓ exploitdb folder present with %d files (exploit code snippets will be bundled)\n", fileCount)
	} else {
		fmt.Println("⚠ exploitdb folder not found - exploit code snippets will not be available")
	}

	// Create the tarball automatically
	tarballPath := filepath.Join(base, "dbs.tar.gz")
	fmt.Printf("Creating tarball: %s\n", tarballPath)

	tarballFile, err := os.Create(tarballPath)
	if err != nil {
		log.Printf("Warning: failed to create tarball file: %v", err)
	} else {
		if err := makeTarball(filepath.Join(base, "dbs"), "dbs", tarballFile); err != nil {
			log.Printf("Warning: failed to create tarball: %v", err)
		} else {
			tarballFile.Close()
			if stat, err := os.Stat(tarballPath); err == nil {
				fmt.Printf("✓ Tarball created: %s (%s)\n", tarballPath, humanize.Bytes(uint64(stat.Size())))
			}
		}
	}

	fmt.Println("fetched", total, "sources ("+humanize.Bytes(numBytesFetched)+")", "in", time.Since(start))
}

func processSource(s *datasource, base string) bool {
	outFilePath := filepath.Join(base, "build", s.name)

	// fetch via HTTP GET from single remote source if provided
	// if multiple sources need to be fetched, the logic can be implemented in the hook
	err := fetchResource(s, outFilePath)
	if err != nil {
		log.Printf("ERROR: failed to fetch resource %s: %v", s.name, err)
		return false
	}

	// run hook
	if s.hook != nil {
		err := s.hook(outFilePath, s, base)
		if err != nil {
			log.Printf("ERROR: hook for %s failed: %v", s.name, err)
			return false
		}
	}

	log.Printf("SUCCESS: processed source %s", s.name)
	return true
}

// fetchResource will attempt to download a resource.
//
// Returns an error instead of log.Fatal so other downloads can continue. A
// per-source overall context budget caps total wall-clock time across all
// retries; this prevents a single blackholed upstream from stalling a rebuild
// for several minutes per run (see sourceTimeout / NC_DBS_SOURCE_TIMEOUT).
func fetchResource(s *datasource, outFilePath string) error {
	if s.url == "" {
		// No URL means this is handled by a hook (like NVD indexing)
		return nil
	}

	fmt.Printf("fetching %s from %s\n", s.name, utils.StripQueryString(s.url))

	ctx, cancel := context.WithTimeout(context.Background(), sourceTimeout())
	defer cancel()

	var (
		numRetries int
		maxRetries = 3
		lastErr    error
	)

	for numRetries <= maxRetries {
		// Stop early if the overall budget has expired.
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			return fmt.Errorf("failed to retrieve data from %s (timeout %s exceeded): %v", s.name, sourceTimeout(), lastErr)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
		if err != nil {
			return fmt.Errorf("failed to build request for %s: %v", s.name, err)
		}

		// execute GET request
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			numRetries++
			// If the failure is from our own deadline elapsing there is no
			// point in sleeping further; surface the error immediately.
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return fmt.Errorf("failed to retrieve data from %s (timeout %s exceeded): %v", s.name, sourceTimeout(), lastErr)
			}
			if numRetries <= maxRetries {
				fmt.Printf("failed to retrieve data from %s (attempt %d/%d): %v - retrying...\n", s.name, numRetries, maxRetries, err)
				if !sleepWithCtx(ctx, time.Duration(numRetries)*time.Second) {
					return fmt.Errorf("failed to retrieve data from %s (timeout %s exceeded): %v", s.name, sourceTimeout(), lastErr)
				}
				continue
			}
			return fmt.Errorf("failed to retrieve data from %s after %d attempts: %v", s.name, maxRetries, lastErr)
		}

		// check status
		if resp.StatusCode != http.StatusOK {
			// drain body so the underlying connection can be reused for the retry
			httputil.DrainAndClose(resp.Body)
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
			numRetries++
			if numRetries <= maxRetries {
				fmt.Printf("received HTTP %d from %s (attempt %d/%d) - retrying...\n", resp.StatusCode, s.name, numRetries, maxRetries)
				if !sleepWithCtx(ctx, time.Duration(numRetries)*time.Second) {
					return fmt.Errorf("failed to retrieve data from %s (timeout %s exceeded): %v", s.name, sourceTimeout(), lastErr)
				}
				continue
			}
			return fmt.Errorf("failed to retrieve data from %s: %s", s.name, lastErr)
		}

		// read body data
		data, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read body data from %s: %v", s.name, err)
		}

		numBytesFetchedMu.Lock()
		numBytesFetched += uint64(len(data))
		numBytesFetchedMu.Unlock()

		// create output file in build folder
		f, err := os.Create(outFilePath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %v", outFilePath, err)
		}

		// write data into file
		_, err = f.Write(data)
		if err != nil {
			f.Close()
			return fmt.Errorf("failed to write data to file %s: %v", outFilePath, err)
		}

		// close the file
		err = f.Close()
		if err != nil {
			return fmt.Errorf("failed to close file %s: %v", outFilePath, err)
		}

		fmt.Printf("successfully downloaded %s (%s)\n", s.name, humanize.Bytes(uint64(len(data))))
		return nil
	}

	return lastErr
}

// sleepWithCtx sleeps for d, but returns false if the context expires first
// so callers can stop the retry loop without further work.
func sleepWithCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
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
