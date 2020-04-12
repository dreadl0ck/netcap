package resolvers

import (
	"os"
	"path/filepath"
)

var (
	Quiet          bool
	dataBaseSource string
)

func Init(c Config, quiet bool) {

	dataBaseSource = os.Getenv("NC_DATABASE_SOURCE")
	if dataBaseSource == "" {
		dataBaseSource = "/usr/local/etc/netcap/dbs"
	}

	Quiet = quiet

	if c.ReverseDNS {
		disableReverseDNS = false
	} else {
		var hostsFound bool
		_, err := os.Stat(filepath.Join(dataBaseSource, "hosts"))
		if err == nil {
			hostsFound = true
		}

		if c.LocalDNS || hostsFound {
			InitLocalDNS()
		}
	}

	if c.MACDB {
		InitMACResolver()
	}
	if c.Ja3DB {
		InitJa3Resolver()
	}
	if c.ServiceDB {
		InitServiceDB()
	}
	if c.GeolocationDB {
		InitGeolocationDB()
	}
}
