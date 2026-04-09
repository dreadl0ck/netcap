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

package proxy

import (
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/table"
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
	table.Render(w, []string{"Proxy Name", "Local", "Remote", "TLS"}, rows)
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
