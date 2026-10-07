package networkdetect

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
)

const FlightSimRevision = "3709d1c6905d9527885c62f66f49a955c7b0d191"

type Indicator struct {
	Value      string `json:"value"`
	Kind       string `json:"kind"`
	Category   string `json:"category"`
	Source     string `json:"source"`
	Version    string `json:"version"`
	ValidFrom  int64  `json:"validFrom"`
	ValidUntil int64  `json:"validUntil"`
}

type Config struct {
	WindowNS        int64       `json:"windowNS"`
	DedupNS         int64       `json:"dedupNS"`
	MaxKeys         int         `json:"maxKeys"`
	MaxFlows        int         `json:"maxFlows"`
	DNSNames        int         `json:"dnsNames"`
	ScanTargets     int         `json:"scanTargets"`
	SMTPHosts       int         `json:"smtpHosts"`
	ICMPEchoes      int         `json:"icmpEchoes"`
	SSHBytes        uint64      `json:"sshBytes"`
	ApprovedSources []string    `json:"approvedSources"`
	Indicators      []Indicator `json:"indicators"`

	// Periodic TCP connection starts from one source to one service. Samples
	// is the number of connection starts examined (0 disables), Jitter the
	// largest accepted coefficient of variation of their intervals.
	BeaconSamples       int     `json:"beaconSamples"`
	BeaconJitter        float64 `json:"beaconJitter"`
	BeaconMinIntervalNS int64   `json:"beaconMinIntervalNS"`
	BeaconWindowNS      int64   `json:"beaconWindowNS"`
}

func DefaultConfig() Config {
	return Config{WindowNS: 60e9, DedupNS: 300e9, MaxKeys: 4096, MaxFlows: 1024, DNSNames: 10, ScanTargets: 10, SMTPHosts: 5, ICMPEchoes: 10, SSHBytes: 10 << 20,
		BeaconSamples: 8, BeaconJitter: 0.1, BeaconMinIntervalNS: 10e9, BeaconWindowNS: 3600e9}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, err
	}
	if info.Size() > 1<<20 {
		return c, errors.New("network detection config exceeds 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("expected one network detection config")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.WindowNS < 1e9 || c.WindowNS > 86400e9 || c.DedupNS < 0 || c.DedupNS > 86400e9 || c.MaxKeys < 1 || c.MaxKeys > 100000 || c.MaxFlows < 1 || c.MaxFlows > 10000 || c.SSHBytes == 0 || len(c.Indicators) > 4096 || len(c.ApprovedSources) > 256 {
		return errors.New("invalid network detection limits")
	}
	for _, n := range []int{c.DNSNames, c.ScanTargets, c.SMTPHosts, c.ICMPEchoes} {
		if n < 2 || n > 128 {
			return errors.New("invalid network detection threshold")
		}
	}
	if c.BeaconSamples != 0 && (c.BeaconSamples < 4 || c.BeaconSamples > maxBeaconTimes || !(c.BeaconJitter > 0 && c.BeaconJitter <= 1) ||
		c.BeaconMinIntervalNS < 1e9 || c.BeaconMinIntervalNS > 3600e9 || c.BeaconWindowNS < 60e9 || c.BeaconWindowNS > 86400e9) {
		return errors.New("invalid beacon detection limits")
	}
	for _, s := range c.ApprovedSources {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err := netip.ParseAddr(s); err != nil {
				return errors.New("invalid approved source")
			}
		}
	}
	for _, i := range c.Indicators {
		if i.Source == "" || i.Version == "" || len(i.Source) > 256 || len(i.Version) > 128 || i.ValidFrom <= 0 || i.ValidUntil <= i.ValidFrom {
			return errors.New("indicator requires bounded provenance and positive capture-time validity")
		}
		if i.Category != "c2" && i.Category != "sink" && i.Category != "imposter" && i.Category != "miner" && i.Category != "oast" {
			return errors.New("unknown indicator category")
		}
		if i.Kind == "ip" {
			if _, err := netip.ParseAddr(i.Value); err != nil {
				return err
			}
		} else if i.Kind != "domain" || !validDomain(i.Value) {
			return errors.New("invalid indicator kind or domain")
		}
	}
	return nil
}

func validDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
