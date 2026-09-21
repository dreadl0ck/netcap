//go:build ja4plus

package ja4plusadapter

import (
	"crypto/x509"

	"github.com/dreadl0ck/ja4plus"
)

const Enabled = true

type ServerHelloData = ja4plus.ServerHelloData
type HTTPData = ja4plus.HTTPData
type TCPFingerprintData = ja4plus.TCPFingerprintData
type SSHStreamData = ja4plus.SSHStreamData
type CertificateFingerprintData = ja4plus.CertificateFingerprintData
type DHCPv4Data = ja4plus.DHCPv4Data

var ComputeJA4S = ja4plus.ComputeJA4S
var ComputeJA4H = ja4plus.ComputeJA4H
var ComputeJA4T = ja4plus.ComputeJA4T
var ComputeJA4TS = ja4plus.ComputeJA4TS
var ComputeJA4L = ja4plus.ComputeJA4L
var NewSSHStreamData = ja4plus.NewSSHStreamData
var ComputeJA4SSH = ja4plus.ComputeJA4SSH
var DetectSessionType = ja4plus.DetectSessionType
var ComputeJA4X = ja4plus.ComputeJA4X
var ComputeJA4XRaw = ja4plus.ComputeJA4XRaw
var ComputeJA4D = ja4plus.ComputeJA4D
var BuildDHCPv4DataFromOptions = ja4plus.BuildDHCPv4DataFromOptions

func ExtractCertificateData(cert *x509.Certificate) *CertificateFingerprintData {
	return ja4plus.ExtractCertificateData(cert)
}
