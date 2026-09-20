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

package tls

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// certificateEntry wraps a TLSCertificate with additional metadata
type certificateEntry struct {
	sync.Mutex
	*types.TLSCertificate
	decoder *decoder.StreamDecoder
}

// atomicCertMap contains all certificates and provides synchronized access
type atomicCertMap struct {
	sync.Mutex
	Items map[string]*certificateEntry // Key is SHA256 fingerprint
}

// Size returns the number of elements in the Items map
func (a *atomicCertMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var certificates = &atomicCertMap{
	Items: make(map[string]*certificateEntry),
}

// ResetCertificates clears all certificates from memory
// This should be called when resetting state between processing different files
func ResetCertificates() {
	certificates.Lock()
	certificates.Items = make(map[string]*certificateEntry)
	certificates.Unlock()
}

// AddOrUpdateCertificate adds a new certificate or updates an existing one
// Returns true if this is a new certificate, false if it was updated
// Exported for testing
func AddOrUpdateCertificate(cert *types.TLSCertificate) bool {
	return addOrUpdateCertificate(cert)
}

// addOrUpdateCertificate is the internal implementation
func addOrUpdateCertificate(cert *types.TLSCertificate) bool {
	certificates.Lock()
	defer certificates.Unlock()

	fingerprint := cert.SHA256Fingerprint
	if entry, exists := certificates.Items[fingerprint]; exists {
		// Update existing certificate
		entry.Lock()
		entry.LastSeen = cert.Timestamp
		entry.SeenCount++
		entry.Unlock()

		tlsLog.Debug("Updated existing certificate",
			zap.String("fingerprint", fingerprint),
			zap.Int64("seenCount", entry.SeenCount),
		)
		return false
	}

	// Add new certificate
	cert.FirstSeen = cert.Timestamp
	cert.LastSeen = cert.Timestamp
	cert.SeenCount = 1

	certificates.Items[fingerprint] = &certificateEntry{
		TLSCertificate: cert,
	}

	tlsLog.Info("Added new certificate",
		zap.String("fingerprint", fingerprint),
		zap.String("subject", cert.SubjectCommonName),
		zap.String("issuer", cert.IssuerCommonName),
	)

	return true
}

// certificateProcessor handles parallel processing of certificate audit records
// when the decoder is stopped and stored certificates are flushed
type certificateProcessor struct {
	sync.Mutex
	workers    []chan *certificateEntry
	numWorkers int
	next       int
	wg         sync.WaitGroup
	numDone    int
	numTotal   int
	bufferSize int
}

// handleCertificate distributes certificates to worker goroutines in round-robin style
func (cp *certificateProcessor) handleCertificate(cert *certificateEntry) {
	cp.wg.Add(1)

	// Send the certificate to the worker routine
	cp.workers[cp.next] <- cert

	// Increment or reset next
	if cp.numWorkers == cp.next+1 {
		cp.next = 0
	} else {
		cp.next++
	}
}

// certificateWorker spawns a new worker goroutine
// and returns a channel for receiving input certificates
func (cp *certificateProcessor) certificateWorker(wg *sync.WaitGroup) chan *certificateEntry {
	// Init channel to receive input certificates
	chanInput := make(chan *certificateEntry, cp.bufferSize)

	// Start worker
	go func() {
		for cert := range chanInput {
			// nil cert is used to exit the loop
			if cert == nil {
				return
			}

			if cert.decoder != nil && cert.decoder.Writer != nil {
				err := cert.decoder.Writer.Write(cert.TLSCertificate)
				if err != nil {
					tlsLog.Error("Failed to write certificate",
						zap.String("fingerprint", cert.SHA256Fingerprint),
						zap.Error(err),
					)
				} else {
					atomic.AddInt64(&cert.decoder.NumRecordsWritten, 1)
				}
			}

			cp.Lock()
			cp.numDone++

			if !decoderconfig.Instance.Quiet {
				utils.ClearLine()
				fmt.Print("processing remaining TLSCertificate audit records... ", "(", cp.numDone, "/", cp.numTotal, ")")
			}

			cp.Unlock()
			wg.Done()
		}
	}()

	return chanInput
}

// initWorkers spawns the configured number of workers
func (cp *certificateProcessor) initWorkers(bufferSize int, numWorkers int) {
	cp.bufferSize = bufferSize
	cp.workers = make([]chan *certificateEntry, numWorkers)

	for i := range cp.workers {
		cp.workers[i] = cp.certificateWorker(&cp.wg)
	}

	cp.numWorkers = len(cp.workers)
}

// flushCertificates writes all cached certificates to disk
func flushCertificates(d *decoder.StreamDecoder) error {
	tlsLog.Info("Flushing certificates", zap.Int("count", certificates.Size()))

	cp := certificateProcessor{}
	cp.initWorkers(decoderconfig.Instance.StreamBufferSize, decoderconfig.Instance.NumStreamWorkers)

	certificates.Lock()
	cp.numTotal = len(certificates.Items)

	// stable output order: Items is a map
	fingerprints := make([]string, 0, len(certificates.Items))
	for fingerprint := range certificates.Items {
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)

	for _, fingerprint := range fingerprints {
		cert := certificates.Items[fingerprint]
		cert.decoder = d
		cp.handleCertificate(cert)
	}
	certificates.Unlock()

	cp.wg.Wait()

	// CRITICAL: Stop all workers by sending nil, then close channels
	for i, w := range cp.workers {
		w <- nil            // Signal worker to exit
		close(w)            // Close the channel
		cp.workers[i] = nil // Nil out reference to help GC
	}

	if !decoderconfig.Instance.Quiet {
		utils.ClearLine()
		fmt.Println("Flushed", cp.numDone, "TLSCertificate audit records")
	}

	return nil
}

// GetCertificateCount returns the number of certificates in the cache
// Exported for testing
func GetCertificateCount() int {
	return certificates.Size()
}

// GetCertificate returns a certificate by its SHA256 fingerprint
// Exported for testing
func GetCertificate(fingerprint string) *types.TLSCertificate {
	certificates.Lock()
	defer certificates.Unlock()

	if entry, exists := certificates.Items[fingerprint]; exists {
		return entry.TLSCertificate
	}
	return nil
}
