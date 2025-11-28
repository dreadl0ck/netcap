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

package software

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"

	"github.com/Jeffail/gabs/v2"
	"github.com/dreadl0ck/netcap/resolvers"
	"go.uber.org/zap"
)

// load JSON database for frontend frameworks from the file system
func loadCmsDB() error {
	// read CMS db JSON
	data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseFolderPath, "cmsdb.json"))
	if err != nil {
		return err
	}

	// use gabs to parse JSON because some fields have varying types...
	jsonParsed, err := gabs.ParseJSON(data)
	if err != nil {
		return err
	}

	// parse the contained regexes and add them to the cmsInfo datastructures
	for framework := range jsonParsed.ChildrenMap() {

		i := new(cmsInfo)

		// fmt.Printf("key: %v, value: %v\n", framework, child.Data().(map[string]interface{}))

		if s, ok := jsonParsed.Path(framework + ".icon").Data().(string); ok {
			i.Icon = s
		}
		if s, ok := jsonParsed.Path(framework + ".cpe").Data().(string); ok {
			i.Cpe = s
		}

		if s, ok := jsonParsed.Path(framework + ".headers").Data().(map[string]interface{}); ok {

			i.Headers = make(map[string]*regexp.Regexp)

			// process headers
			for name, re := range s {
				// add to map for lookups by name during runtime
				CMSHeaders[name] = struct{}{}

				// compile the supplied regex
				r, errCompile := regexp.Compile(fmt.Sprint(re))
				if errCompile != nil {
					softwareLog.Info("failed to compile regex from CMS db HEADER",
						zap.Error(errCompile),
						zap.String("re", fmt.Sprint(re)),
						zap.String("framework", framework),
					)
				} else {
					i.Headers[name] = r
				}
			}
		}

		if s, ok := jsonParsed.Path(framework + ".cookies").Data().(map[string]interface{}); ok {

			i.Cookies = make(map[string]*regexp.Regexp)

			// process cookies
			for name, re := range s {
				// add to map for lookups by name during runtime
				CMSCookies[name] = struct{}{}

				// compile the supplied regex
				r, errCompile := regexp.Compile(fmt.Sprint(re))
				if errCompile != nil {
					softwareLog.Info("failed to compile regex from CMS db COOKIE",
						zap.Error(errCompile),
						zap.String("re", fmt.Sprint(re)),
						zap.String("framework", framework),
					)
				} else {
					i.Cookies[name] = r
				}
			}
		}

		if s, ok := jsonParsed.Path(framework + ".js").Data().(map[string]interface{}); ok {
			m := make(map[string]string)
			for k, v := range s {
				m[k] = fmt.Sprint(v)
			}
			i.Js = m
		}

		if s, ok := jsonParsed.Path(framework + ".meta").Data().(map[string]interface{}); ok {
			m := make(map[string]string)
			for k, v := range s {
				m[k] = fmt.Sprint(v)
			}
			i.Meta = m
		}

		if s, ok := jsonParsed.Path(framework + ".website").Data().(string); ok {
			i.Website = s
		}

		if s, ok := jsonParsed.Path(framework + ".implies").Data().(string); ok {
			i.Implies = []string{s}
		}
		if s, ok := jsonParsed.Path(framework + ".implies").Data().([]string); ok {
			i.Implies = s
		}

		if s, ok := jsonParsed.Path(framework + ".script").Data().(string); ok {
			i.Script = []string{s}
		}
		if s, ok := jsonParsed.Path(framework + ".script").Data().([]string); ok {
			i.Script = s
		}

		if s, ok := jsonParsed.Path(framework + ".html").Data().(string); ok {
			i.HTML = []string{s}
		}
		if s, ok := jsonParsed.Path(framework + ".html").Data().([]string); ok {
			i.HTML = s
		}

		// spew.Dump(i)

		cmsDB[framework] = i
	}

	return nil
}
