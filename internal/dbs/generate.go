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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/utils"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/internal/archive"
	"github.com/dreadl0ck/netcap/internal/httputil"
)

// defaultSourceTimeout caps the total wall-clock time spent fetching a single
// data source (including retries and backoff). It prevents a blackholed
// upstream from keeping the rebuild stalled for minutes per run. The default
// mirrors the slowest known good source on a healthy network
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

// skippedSourceNames returns the set of data-source names operators have
// asked to skip via the NC_DBS_SKIP_SOURCES env variable (comma-separated,
// values matched against datasource.name). Used to bypass upstreams that
// are known-bad from this network without rebuilding the image, e.g.
// NC_DBS_SKIP_SOURCES=hasshdb.json.
func skippedSourceNames() map[string]struct{} {
	raw := os.Getenv("NC_DBS_SKIP_SOURCES")
	if raw == "" {
		return nil
	}
	out := make(map[string]struct{})
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out[name] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// activeSources returns the data-source list with operator-requested skips
// applied. The first call per process logs which sources were skipped.
func activeSources() []*datasource {
	skip := skippedSourceNames()
	if len(skip) == 0 {
		return sources
	}
	out := make([]*datasource, 0, len(sources))
	skipped := make([]string, 0, len(skip))
	for _, s := range sources {
		if _, drop := skip[s.name]; drop {
			skipped = append(skipped, s.name)
			continue
		}
		out = append(out, s)
	}
	logSkippedSourcesOnce(skipped)
	return out
}

var logSkippedOnce sync.Once

func logSkippedSourcesOnce(names []string) {
	if len(names) == 0 {
		return
	}
	logSkippedOnce.Do(func() {
		log.Printf("dbs: skipping %d data source(s) per NC_DBS_SKIP_SOURCES: %s",
			len(names), strings.Join(names, ", "))
	})
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
	// Candidate sources only; acquisition does not authorize publication.
	makeSource("https://raw.githubusercontent.com/ua-parser/uap-core/73e7340c3ed8055051607b296bf46ead7aa5f19e/regexes.yaml", "", moveToDbs),

	makeSource("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv", "", moveToDbs),

	// BuildVulnDB indexes complete NVD feeds only.
	makeSource("", "nvd", downloadNVD),
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

func downloadNVD(_ string, _ *datasource, base string) error {

	for _, year := range yearRange(nvdStartYear, time.Now().Year()) {

		s := makeSource(fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%s.json.gz", year), "", nil)
		err := fetchResource(s, filepath.Join(base, "build", s.name))
		if err != nil {
			return fmt.Errorf("required NVD year %s unavailable: %w", year, err)
		}
	}

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
