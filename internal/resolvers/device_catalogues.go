package resolvers

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/devicecatalog"
	"github.com/dreadl0ck/netcap/internal/enrichment"
)

type DeviceCatalogueStatus struct {
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Version      string `json:"version,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Attribution  string `json:"attribution"`
	SourceURL    string `json:"source_url"`
	LicenseURL   string `json:"license_url"`
	DownloadFile string `json:"download_file"`
	NoticesFile  string `json:"notices_file"`
}

func deviceCatalogueStatus(kind string) DeviceCatalogueStatus {
	status := DeviceCatalogueStatus{Kind: kind, State: "not-initialized", Attribution: "FingerBank / Inverse inc., Copyright (C) 2008-2013; derivative under ODbL 1.0, contents under DbCL 1.0", SourceURL: "https://github.com/inverse-inc/packetfence/blob/de2f9678434a6f922fc7ce66e9fd3191606ed80f/conf/dhcp_fingerprints.conf", LicenseURL: "https://opendatacommons.org/licenses/odbl/1-0/", DownloadFile: "dhcp-fingerprints-odbl.json", NoticesFile: enrichment.NoticesName}
	if kind == "mac" {
		status.Attribution = "IEEE registered organizations; secondary Debian ieee-data 20260625 nonassertion evidence accepted; gopacket v1.7.2 fallback"
		status.SourceURL = "https://standards-oui.ieee.org/"
		status.LicenseURL = "https://metadata.ftp-master.debian.org/changelogs/main/i/ieee-data/ieee-data_20260625_copyright"
		status.DownloadFile = "mac-organizations.json"
	}
	return status
}

var deviceStatus struct {
	sync.Mutex
	MAC, DHCP DeviceCatalogueStatus
}

// DeviceCatalogueStatuses is a read-only source summary for API/Pro consumers.
// It never resolves a channel, reads a file or performs network I/O.
func DeviceCatalogueStatuses() []DeviceCatalogueStatus {
	deviceStatus.Lock()
	defer deviceStatus.Unlock()
	dhcp, mac := deviceStatus.DHCP, deviceStatus.MAC
	if dhcp.Kind == "" {
		dhcp = deviceCatalogueStatus("dhcp")
	}
	if mac.Kind == "" {
		mac = deviceCatalogueStatus("mac")
	}
	return []DeviceCatalogueStatus{dhcp, mac}
}

func initDeviceCatalogues(mac, dhcp bool) {
	initDeviceCataloguesWithTrust(mac, dhcp, enrichment.SigningRoot(), time.Now())
}

func initDeviceCataloguesWithTrust(mac, dhcp bool, trust ed25519.PublicKey, now time.Time) {
	deviceStatus.Lock()
	defer deviceStatus.Unlock()
	var members map[string][]byte
	var resolveErr error
	if (mac && os.Getenv("NC_MAC_CATALOGUE") == "") || (dhcp && os.Getenv("NC_DHCP_CATALOGUE") == "") {
		members, resolveErr = enrichment.Open(enrichment.Root(ConfigRootPath), trust, now)
	}
	for _, kind := range []string{"dhcp", "mac"} {
		if kind == "dhcp" && !dhcp || kind == "mac" && !mac {
			continue
		}
		status := deviceCatalogueStatus(kind)
		env, previous := "NC_DHCP_CATALOGUE", deviceStatus.DHCP
		if kind == "mac" {
			env, previous = "NC_MAC_CATALOGUE", deviceStatus.MAC
		}
		path, err := os.Getenv(env), resolveErr
		if path != "" {
			err = nil
			status.State = "explicit-trusted-override"
			if core, e := filepath.Abs(DataBaseFolderPath); e == nil {
				if resolved, e := filepath.EvalSymlinks(core); e == nil {
					core = resolved
				}
				explicit, e := filepath.Abs(path)
				if resolved, resolveErr := filepath.EvalSymlinks(explicit); resolveErr == nil {
					explicit = resolved
				}
				if e == nil {
					if rel, e := filepath.Rel(core, explicit); e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						err = fmt.Errorf("explicit device catalogue must be outside core database directory")
					}
				}
			}
		} else if err == nil {
			status.State = "verified-installed"
		}
		if err == nil {
			if path == "" {
				data, ok := members[status.DownloadFile]
				if !ok {
					err = fmt.Errorf("verified channel has no %s", status.DownloadFile)
				} else if kind == "mac" {
					var c *devicecatalog.MAC
					c, err = devicecatalog.ParseMAC(data)
					if err == nil {
						macCatalogue.Store(c)
					}
				} else {
					var c *devicecatalog.DHCP
					c, err = devicecatalog.ParseDHCP(data)
					if err == nil {
						dhcpCatalogue.Store(c)
					}
				}
			} else if kind == "mac" {
				err = LoadMACCatalogue(path)
			} else {
				err = LoadDHCPCatalogue(path)
			}
		}
		if err != nil {
			status.Reason = err.Error()
			status.State = "unavailable"
			if kind == "mac" {
				status.State = "builtin-fallback"
			}
			if kind == "mac" && macCatalogue.Load() != nil || kind == "dhcp" && dhcpCatalogue.Load() != nil {
				if previous.Kind != "" {
					status = previous
				}
				status.Kind = kind
				status.State = "retained-after-error"
				status.Reason = err.Error()
			}
			resolverLog.Warn("optional " + kind + " catalogue: " + status.State + ": " + err.Error())
		} else {
			resolverLog.Info("optional " + kind + " catalogue: " + status.State)
		}
		if kind == "mac" {
			if c := macCatalogue.Load(); c != nil {
				status.Version = c.Version
			}
			deviceStatus.MAC = status
		} else {
			if c := dhcpCatalogue.Load(); c != nil {
				status.Version = c.Version
			}
			deviceStatus.DHCP = status
		}
	}
}
