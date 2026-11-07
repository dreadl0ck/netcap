package firewallaudit

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/responseactions"
)

// ConfigJSON matches the firewall command's effects file (durations are JSON
// nanoseconds). It deliberately contains no endpoint supplied by a policy.
type ConfigJSON struct {
	Scopes              map[string]responseactions.Scope `json:"scopes"`
	QueueSize           int                              `json:"queueSize"`
	MaxPending          int                              `json:"maxPending"`
	MaxReceipts         int                              `json:"maxReceipts"`
	Retention           time.Duration                    `json:"retention"`
	CA                  string                           `json:"ca"`
	Cert                string                           `json:"cert"`
	Key                 string                           `json:"key"`
	MaxActionsPerMinute int                              `json:"maxActionsPerMinute,omitempty"`
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("firewallaudit: cannot open configuration")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("firewallaudit: configuration unreadable or oversized")
	}
	return raw, nil
}

// LoadConfig reads configuration and TLS material without creating a broker or
// making network requests. New performs broker scope/token admission separately.
func LoadConfig(path string) (responseactions.Config, error) {
	raw, err := readBounded(path, 1<<20)
	if err != nil {
		return responseactions.Config{}, err
	}
	var f ConfigJSON
	if firewallstate.Decode(raw, &f) != nil {
		return responseactions.Config{}, errors.New("firewallaudit: invalid effects configuration")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if f.CA != "" {
		raw, err = readBounded(f.CA, 1<<20)
		if err != nil {
			return responseactions.Config{}, err
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(raw) {
			return responseactions.Config{}, errors.New("firewallaudit: invalid effects CA")
		}
	}
	if (f.Cert == "") != (f.Key == "") {
		return responseactions.Config{}, errors.New("firewallaudit: effects certificate and key must be paired")
	}
	if f.Cert != "" {
		cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
		if err != nil {
			return responseactions.Config{}, errors.New("firewallaudit: invalid effects certificate pair")
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return responseactions.Config{Scopes: f.Scopes, QueueSize: f.QueueSize, MaxPending: f.MaxPending, MaxReceipts: f.MaxReceipts, Retention: f.Retention, TLSConfig: tc, MaxActionsPerMinute: f.MaxActionsPerMinute}, nil
}
