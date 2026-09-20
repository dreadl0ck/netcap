//go:build !ja4plus

package ja4plusadapter

import "crypto/x509"

const Enabled = false

type ServerHelloData struct {
	Version       uint16
	CipherSuite   uint16
	Extensions    []uint16
	SupportedVers uint16
	IsQUIC        bool
	ALPN          string
}

type HTTPData struct {
	Method         string
	Version        string
	HeaderOrder    []string
	HasCookie      bool
	CookieFields   []string
	AcceptLanguage string
}

type TCPFingerprintData struct {
	WindowSize  uint16
	Options     []uint8
	MSS         uint16
	WindowScale uint8
	IsSYN       bool
	IsSYNACK    bool
}

type SSHStreamData struct{}

func (*SSHStreamData) AddClientPacket(int) {}
func (*SSHStreamData) AddServerPacket(int) {}
func (*SSHStreamData) AddClientACK()       {}
func (*SSHStreamData) AddServerACK()       {}

type CertificateFingerprintData struct{}
type DHCPv4Data struct{}

func ComputeJA4S(*ServerHelloData) string     { return "" }
func ComputeJA4H(*HTTPData) string            { return "" }
func ComputeJA4T(*TCPFingerprintData) string  { return "" }
func ComputeJA4TS(*TCPFingerprintData) string { return "" }
func ComputeJA4L(int64, uint8) string         { return "" }
func NewSSHStreamData() *SSHStreamData        { return &SSHStreamData{} }
func ComputeJA4SSH(*SSHStreamData) string     { return "" }
func DetectSessionType(string) string         { return "" }
func ExtractCertificateData(*x509.Certificate) *CertificateFingerprintData {
	return &CertificateFingerprintData{}
}
func ComputeJA4X(*CertificateFingerprintData) string    { return "" }
func ComputeJA4XRaw(*CertificateFingerprintData) string { return "" }
func ComputeJA4D(*DHCPv4Data) string                    { return "" }
func BuildDHCPv4DataFromOptions(uint8, uint8, []uint8, []uint8, string, string) *DHCPv4Data {
	return &DHCPv4Data{}
}
