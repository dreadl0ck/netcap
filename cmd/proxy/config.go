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
	yaml "gopkg.in/yaml.v2"
)

var (
	// config for the commandline application
	c *Config
)

// Config represents the proxy configuration
type Config struct {

	// Proxies map holds all reverse proxies
	Proxies map[string]ReverseProxyConfig `yaml:"proxies"`

	// CertFile for TLS secured connections
	CertFile string `yaml:"certFile"`

	// KeyFile for TLS secured connections
	KeyFile string `yaml:"keyFile"`

	// Logdir is used as destination for the logfile
	Logdir string `yaml:"logdir"`
}

// Dump prints the current configuration
func (c Config) Dump(w io.Writer) {

	fmt.Println("logDir:", c.Logdir)

	// init rows for table
	var rows = [][]string{}

	// gather infos from proxies
	for name, p := range c.Proxies {
		rows = append(rows, []string{name, p.Local, p.Remote, strconv.FormatBool(p.TLS)})
	}

	// print table
	tui.Table(w, []string{"Proxy Name", "Local", "Remote", "TLS"}, rows)
	fmt.Println()
}

// ParseConfiguration reads the config file and returns a config instance
func ParseConfiguration(path string) (*Config, error) {

	// read file at path
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// init config instance
	var c = new(Config)

	// unmarshal data into instance
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
