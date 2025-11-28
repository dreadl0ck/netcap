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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// reverseProxy represents a named reverse proxy
// that uses a custom http.Transport to export netcap audit records.
type reverseProxy struct {
	Name   string
	rp     *httputil.ReverseProxy
	writer io.AuditRecordWriter
}

// ServeHTTP implements the http.Handler interface.
func (p *reverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.rp.ServeHTTP(w, r)
}

// reverseProxyConfig represents the configuration of a single reverse proxy
// if the TLS field is set to true
// paths to the cert and key files must be specified.
type reverseProxyConfig struct {

	// Remote endpoint address
	Remote string `yaml:"remote"`

	// Local endpoint address
	Local string `yaml:"local"`

	// TLS for local endpoint
	TLS bool `yaml:"tls"`
}

// newReverseProxy creates a reverseProxy instance for the given target URL
// and sets the specified name.
func newReverseProxy(proxyName string, targetURL *url.URL) *reverseProxy {
	// instantiate proxy
	proxy := &reverseProxy{
		Name: proxyName,
		rp:   httputil.NewSingleHostReverseProxy(targetURL),
	}

	// overwrite error handler to collect the error messages
	proxy.rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// reply with BadGateway
		w.WriteHeader(http.StatusBadGateway)
		proxyLog.Error("reverse proxy encountered an error",
			zap.String("host", r.URL.Host),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
			zap.String("error", err.Error()),
		)
	}

	// overwrite transport for reverse proxy
	// (needed to implement a custom roundtripper that collects metrics for us)
	proxy.rp.Transport = &netcapTransport{

		targetURL: targetURL,
		proxyName: proxyName,
		proxy:     proxy,

		// init round tripper
		rt: &http.Transport{

			// setup DialContext
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(flagDialTimeout) * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,

			Proxy:        http.ProxyFromEnvironment,
			MaxIdleConns: flagMaxIdleConns,

			// set timeouts
			IdleConnTimeout:       time.Duration(flagIdleConnTimeout) * time.Second,
			TLSHandshakeTimeout:   time.Duration(flagTLSHandshakeTimeout) * time.Second,
			ExpectContinueTimeout: 5 * time.Second,

			/* #nosec */
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: flagSkipTLSVerify,
			},
		},
	}

	proxy.writer = io.NewAuditRecordWriter(&io.WriterConfig{
		CSV:              false,
		Proto:            true,
		JSON:             false,
		Name:             "HTTP[" + targetURL.Host + "]",
		Buffer:           false,
		Compress:         false,
		Out:              "",
		MemBufferSize:    flagMemBufferSize,
		Source:           targetURL.String(),
		Version:          netcap.Version,
		IncludesPayloads: false,
		StartTime:        time.Now(),
	})

	err := proxy.writer.WriteHeader(types.Type_NC_HTTP)
	if err != nil {
		fmt.Println("failed to write file header:", err)
	}

	return proxy
}
