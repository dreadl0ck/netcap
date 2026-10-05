package dbs

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
)

const dbipDownloadURL = "https://download.db-ip.com/free"

type GeoIPSource struct {
	File    string `json:"file"`
	Release string `json:"release"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	License string `json:"license"`
}

func validateDBIP(dir string) ([]GeoIPSource, error) {
	body, err := os.ReadFile(filepath.Join(dir, "geoip-sources.json"))
	if err != nil {
		return nil, err
	}
	var manifest []GeoIPSource
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, err
	}
	if len(manifest) != 2 {
		return nil, fmt.Errorf("DB-IP manifest must contain city and ASN")
	}
	for i, kind := range []string{"city", "asn"} {
		entry := manifest[i]
		file := "dbip-" + kind + "-lite.mmdb"
		if entry.File != file || entry.License != "https://creativecommons.org/licenses/by/4.0/" {
			return nil, fmt.Errorf("invalid DB-IP manifest entry: %s", entry.File)
		}
		if _, err := time.Parse("2006-01", entry.Release); err != nil {
			return nil, err
		}
		if entry.Release != manifest[0].Release {
			return nil, fmt.Errorf("DB-IP release months differ")
		}
		f, err := os.Open(filepath.Join(dir, file))
		if err != nil {
			return nil, err
		}
		info, statErr := os.Lstat(filepath.Join(dir, file))
		if statErr != nil || !info.Mode().IsRegular() {
			f.Close()
			return nil, fmt.Errorf("DB-IP source is not a regular file: %s", file)
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		if hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return nil, fmt.Errorf("DB-IP hash mismatch: %s", file)
		}
		dbKind := "City"
		if kind == "asn" {
			dbKind = "ASN"
		}
		r, err := resolvers.OpenGeoDatabase(filepath.Join(dir, file), "dbip", dbKind)
		if err != nil {
			return nil, err
		}
		buildMonth := time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format("2006-01")
		r.Close()
		if buildMonth != entry.Release {
			return nil, fmt.Errorf("DB-IP build month mismatch: %s", file)
		}
	}
	return manifest, nil
}

func validateGeoIPBundle(dir string) error {
	for _, file := range []string{"dbip-city-lite.mmdb", "dbip-asn-lite.mmdb", "geoip-sources.json"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err == nil {
			_, err := validateDBIP(dir)
			return err
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func copyDBIP(from, to string) error {
	manifest, err := validateDBIP(from)
	if err != nil {
		return err
	}
	for _, file := range []string{manifest[0].File, manifest[1].File, "geoip-sources.json"} {
		in, err := os.Open(filepath.Join(from, file))
		if err != nil {
			return err
		}
		out, err := os.Create(filepath.Join(to, file))
		if err != nil {
			in.Close()
			return err
		}
		_, err = io.Copy(out, in)
		in.Close()
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func fetchDBIPMonth(ctx context.Context, client *http.Client, origin, month, dir string) error {
	var manifest []GeoIPSource
	for _, kind := range []string{"city", "asn"} {
		url := fmt.Sprintf("%s/dbip-%s-lite-%s.mmdb.gz", origin, kind, month)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "netcap-dbs")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("DB-IP %s: HTTP %d", month, resp.StatusCode)
		}
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return err
		}
		file := "dbip-" + kind + "-lite.mmdb"
		out, err := os.Create(filepath.Join(dir, file))
		if err != nil {
			gz.Close()
			resp.Body.Close()
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(gz, 512<<20))
		closeErr := out.Close()
		gz.Close()
		resp.Body.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n == 512<<20 {
			return fmt.Errorf("DB-IP decompressed size exceeds limit")
		}
		dbKind := "City"
		if kind == "asn" {
			dbKind = "ASN"
		}
		reader, err := resolvers.OpenGeoDatabase(filepath.Join(dir, file), "dbip", dbKind)
		if err != nil {
			return err
		}
		verifyErr := reader.Verify()
		reader.Close()
		if verifyErr != nil {
			return fmt.Errorf("invalid DB-IP database: %w", verifyErr)
		}
		manifest = append(manifest, GeoIPSource{file, month, url, hex.EncodeToString(h.Sum(nil)), "https://creativecommons.org/licenses/by/4.0/"})
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip-sources.json"), body, 0o644); err != nil {
		return err
	}
	_, err = validateDBIP(dir)
	return err
}

func ensureDBIP(dst, cache string, now time.Time, client *http.Client, origin string) error {
	month := now.UTC().Format("2006-01")
	if old, err := validateDBIP(cache); err == nil && old[0].Release == month {
		return copyDBIP(cache, dst)
	}
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(cache), "dbip-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	ctx, cancel := context.WithTimeout(context.Background(), 2*sourceTimeout())
	defer cancel()
	var fetchErr error
	for _, release := range []string{month, now.UTC().AddDate(0, 0, -now.UTC().Day()).Format("2006-01")} {
		fetchErr = fetchDBIPMonth(ctx, client, origin, release, stage)
		if fetchErr == nil {
			if err := copyDBIP(stage, dst); err != nil {
				return err
			}
			if err := os.RemoveAll(cache); err != nil {
				return err
			}
			return os.Rename(stage, cache)
		}
	}
	log.Printf("DB-IP download unavailable; trying verified cache: %v", fetchErr)
	if err := copyDBIP(cache, dst); err != nil {
		return fmt.Errorf("DB-IP download failed (%v); no valid cache: %w", fetchErr, err)
	}
	return nil
}

func includeDBIP(base, cache string) error {
	return ensureDBIP(filepath.Join(base, "dbs"), cache, time.Now(), http.DefaultClient, dbipDownloadURL)
}
