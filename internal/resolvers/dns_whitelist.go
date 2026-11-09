// Copyright (c) Philipp Mieden. SPDX-License-Identifier: GPL-3.0-or-later
package resolvers

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const MaxPopularityBytes = 128 << 20
const MaxPopularityRows = 1_000_000
const ManagedPopularityFile = "netapi-top1m.csv"

// PopularityStats includes rejected input; failed loads never publish partial data.
type PopularityStats struct{ Rows, Loaded, Duplicates, Invalid, Skipped int }
type DomainPopularityList struct{ domains map[string]struct{} }

var popularity atomic.Pointer[DomainPopularityList]
var popularityInit sync.Mutex
var popularityKey string

func ValidatePopularityFormat(format string) error {
	if format != "" && format != "rank-domain" && format != "netapi" && format != "majestic" {
		return fmt.Errorf("unknown domain-popularity-format %q", format)
	}
	return nil
}

// ExternalPopularityPath resolves symlinks, including existing ancestors of a
// missing managed directory, before checking containment.
func ExternalPopularityPath(path, managed string) (string, error) {
	inside := func(file, root string) bool {
		rel, err := filepath.Rel(root, file)
		return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
	}
	fileAbs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(managed)
	if err != nil {
		return "", err
	}
	if inside(fileAbs, rootAbs) {
		return "", errors.New("domain-popularity-list must be outside the managed database directory")
	}
	resolve := func(p string) (string, error) {
		p, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		var tail []string
		for {
			resolved, err := filepath.EvalSymlinks(p)
			if err == nil {
				for i := len(tail) - 1; i >= 0; i-- {
					resolved = filepath.Join(resolved, tail[i])
				}
				return resolved, nil
			}
			if !os.IsNotExist(err) {
				return "", err
			}
			parent := filepath.Dir(p)
			if parent == p {
				return "", err
			}
			tail = append(tail, filepath.Base(p))
			p = parent
		}
	}
	file, err := resolve(path)
	if err != nil {
		return "", err
	}
	root, err := resolve(managed)
	if err != nil {
		return "", err
	}
	if inside(file, root) || inside(fileAbs, root) {
		return "", errors.New("domain-popularity-list must be outside the managed database directory")
	}
	return file, nil
}

func popularityHostname(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, ":/\\@*\x00") {
		return "", errors.New("invalid domain")
	}
	host, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) > 253 || net.ParseIP(host) != nil {
		return "", errors.New("invalid domain or IP")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid DNS character")
			}
		}
	}
	return host, nil
}

func popularityDomain(raw string) (string, error) {
	host, err := popularityHostname(raw)
	if err != nil {
		return "", err
	}
	suffix, icann := publicsuffix.PublicSuffix(host)
	if !icann && !strings.Contains(suffix, ".") {
		return "", errors.New("unknown public suffix")
	}
	return publicsuffix.EffectiveTLDPlusOne(host)
}

// LoadDomainPopularityList reads an explicit local file only: rank-domain has
// no header, netapi requires NetAPI_Rank,Domain, majestic its 12-column header.
func LoadDomainPopularityList(path, format, managed string) (*DomainPopularityList, PopularityStats, error) {
	path, err := ExternalPopularityPath(path, managed)
	if err != nil {
		return nil, PopularityStats{}, err
	}
	return loadDomainPopularityList(path, format, false)
}

// LoadManagedDomainPopularityList validates the dedicated NetAPI member only.
func LoadManagedDomainPopularityList(dir string) (*DomainPopularityList, PopularityStats, error) {
	return loadDomainPopularityList(filepath.Join(dir, ManagedPopularityFile), "netapi", true)
}

func loadDomainPopularityList(path, format string, managedFeed bool) (*DomainPopularityList, PopularityStats, error) {
	stats := PopularityStats{}
	if format == "" {
		format = "rank-domain"
	}
	if err := ValidatePopularityFormat(format); err != nil {
		return nil, stats, err
	}
	meta, err := os.Stat(path)
	if err != nil {
		return nil, stats, err
	}
	if !meta.Mode().IsRegular() {
		return nil, stats, errors.New("popularity input must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, stats, err
	}
	defer f.Close()
	meta, err = f.Stat()
	if err != nil {
		return nil, stats, err
	}
	if !meta.Mode().IsRegular() || meta.Size() > MaxPopularityBytes {
		return nil, stats, errors.New("popularity input must be a regular file at most 128 MiB")
	}
	limited := &io.LimitedReader{R: f, N: MaxPopularityBytes + 1}
	r := csv.NewReader(limited)
	r.FieldsPerRecord = 2
	domainCol := 1
	if format == "majestic" {
		r.FieldsPerRecord = 12
		domainCol = 2
	}
	if format != "rank-domain" {
		header, e := r.Read()
		expected := "NetAPI_Rank,Domain"
		if format == "majestic" {
			expected = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs"
		}
		if e != nil || strings.Join(header, ",") != expected {
			stats.Invalid++
			return nil, stats, errors.New("invalid popularity CSV header")
		}
	}
	list := &DomainPopularityList{domains: make(map[string]struct{})}
	ranks := make(map[uint64]struct{})
	for {
		row, e := r.Read()
		if e == io.EOF {
			break
		}
		stats.Rows++
		if stats.Rows > MaxPopularityRows {
			return nil, stats, errors.New("popularity CSV exceeds 1000000 rows")
		}
		if e != nil {
			stats.Invalid++
			return nil, stats, fmt.Errorf("popularity row %d: %w", stats.Rows, e)
		}
		rank, e := strconv.ParseUint(row[0], 10, 64)
		for _, c := range row[0] {
			if c < '0' || c > '9' {
				e = errors.New("invalid rank")
			}
		}
		domain, de := popularityDomain(row[domainCol])
		host, he := popularityHostname(row[domainCol])
		// Daily feeds may contain retired TLDs, PSL roots or non-registrable
		// hostnames. Omit them rather than broadening suppression to tenants.
		skip := managedFeed && he == nil && (de != nil || domain != host)
		if e != nil || rank == 0 || he != nil || (!skip && (de != nil || domain != host)) {
			stats.Invalid++
			return nil, stats, fmt.Errorf("invalid popularity rank or registrable domain at row %d", stats.Rows)
		}
		if _, exists := ranks[rank]; exists {
			stats.Invalid++
			return nil, stats, fmt.Errorf("duplicate popularity rank at row %d", stats.Rows)
		}
		ranks[rank] = struct{}{}
		if skip {
			stats.Skipped++
			continue
		}
		if _, exists := list.domains[domain]; exists {
			stats.Duplicates++
			continue
		}
		list.domains[domain] = struct{}{}
		stats.Loaded++
	}
	if limited.N <= 0 {
		return nil, stats, errors.New("popularity CSV exceeds 128 MiB")
	}
	if stats.Loaded == 0 {
		return nil, stats, errors.New("empty popularity CSV")
	}
	return list, stats, nil
}

// ContainsDNS reports popularity, never safety. PRIVATE PSL rules isolate tenants.
func (l *DomainPopularityList) ContainsDNS(name string) bool {
	if l == nil {
		return false
	}
	domain, err := popularityDomain(name)
	if err != nil {
		return false
	}
	_, ok := l.domains[domain]
	return ok
}
func (l *DomainPopularityList) ContainsHTTP(host string) bool {
	if strings.Contains(host, ":") {
		name, port, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		n, err := strconv.ParseUint(port, 10, 16)
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
		if err != nil || n == 0 {
			return false
		}
		host = name
	}
	return l.ContainsDNS(host)
}

// InitDNSWhitelist loads each configuration once; failures never retain stale entries.
func InitDNSWhitelist() error {
	popularityInit.Lock()
	defer popularityInit.Unlock()
	path, format := CurrentConfig.DomainPopularityList, CurrentConfig.DomainPopularityFormat
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%t", path, format, DataBaseFolderPath, CurrentConfig.DisableDomainPopularity)
	if key == popularityKey && (popularity.Load() != nil || CurrentConfig.DisableDomainPopularity) {
		return nil
	}
	popularity.Store(nil)
	popularityKey = ""
	if CurrentConfig.DisableDomainPopularity {
		popularityKey = key
		return nil
	}
	var list *DomainPopularityList
	var stats PopularityStats
	var err error
	if path == "" {
		list, stats, err = LoadManagedDomainPopularityList(DataBaseFolderPath)
	} else {
		list, stats, err = LoadDomainPopularityList(path, format, DataBaseFolderPath)
	}
	if path == "" && os.IsNotExist(err) {
		return nil // The optional managed list is absent; no popularity suppression.
	}
	log.Printf("domain popularity: rows=%d loaded=%d duplicates=%d invalid=%d skipped=%d error=%v", stats.Rows, stats.Loaded, stats.Duplicates, stats.Invalid, stats.Skipped, err)
	if err != nil {
		return fmt.Errorf("domain popularity: %w (update databases or use --no-domain-popularity)", err)
	}
	popularity.Store(list)
	popularityKey = key
	return nil
}

// IsWhitelistedDomain is a legacy name for popularity suppression only.
func IsWhitelistedDomain(domain string) bool { return popularity.Load().ContainsDNS(domain) }
func IsPopularHTTPHost(host string) bool     { return popularity.Load().ContainsHTTP(host) }
