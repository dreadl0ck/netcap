package resolvers

type Config struct {
	ReverseDNS    bool
	LocalDNS      bool
	MACDB         bool
	Ja3DB         bool
	ServiceDB     bool
	GeolocationDB bool
}

var DefaultConfig = Config{
	ReverseDNS:    false,
	LocalDNS:      false,
	MACDB:         true,
	Ja3DB:         true,
	ServiceDB:     true,
	GeolocationDB: true,
}
