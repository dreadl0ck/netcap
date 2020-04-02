package resolvers

import "os"

var (
	Quiet bool
	dataBaseSource string
)

type Config struct {
	ReverseDNS      bool
	LocalDNS        bool
	MACDB           bool
	Ja3DB           bool
	ServiceDB       bool
	GeolocationDB   bool
}

func Init(c Config, quiet bool) {

	dataBaseSource = os.Getenv("NETCAP_DATABASE_SOURCE")
	if dataBaseSource == "" {
		dataBaseSource = "/usr/local/etc/netcap/dbs"
	}

	Quiet = quiet

	if c.ReverseDNS {
		disableReverseDNS = false
	}
	if c.LocalDNS {
		InitLocalDNS()
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