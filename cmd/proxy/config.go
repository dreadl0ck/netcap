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

package proxy

import (
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	"github.com/evilsocket/islazy/tui"
	"gopkg.in/yaml.v2"
)

// config for the commandline application.
var c = new(config)

// config represents the proxy configuration.
type config struct {

	// Proxies map holds all reverse proxies
	Proxies map[string]reverseProxyConfig `yaml:"proxies"`

	// CertFile for TLS secured connections
	CertFile string `yaml:"certFile"`

	// KeyFile for TLS secured connections
	KeyFile string `yaml:"keyFile"`

	// Logdir is used as destination for the logfile
	Logdir string `yaml:"logdir"`
}

// dump prints the current configuration.
func (c config) dump(w io.Writer) {
	fmt.Println("logDir:", c.Logdir)

	// init rows for table
	var (
		rows  = make([][]string, len(c.Proxies))
		index int
	)

	// gather infos from proxies
	for name, p := range c.Proxies {
		rows[index] = []string{name, p.Local, p.Remote, strconv.FormatBool(p.TLS)}
		index++
	}

	// print table
	tui.Table(w, []string{"Proxy Name", "Local", "Remote", "TLS"}, rows)
	fmt.Println()
}

// parseConfiguration reads the config file and returns a config instance.
func parseConfiguration(path string) (*config, error) {
	// read file at path
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// unmarshal data into instance
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
