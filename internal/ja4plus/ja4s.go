//go:build ja4plus

package ja4plus

import (
	"fmt"
	"strings"
)

const (
	extensionSNI  uint16 = 0
	extensionALPN uint16 = 16
)

// ServerHelloData contains the data needed to compute a JA4S fingerprint.
type ServerHelloData struct {
	Version       uint16
	CipherSuite   uint16
	Extensions    []uint16
	SupportedVers uint16
	IsQUIC        bool
	ALPN          string
}

// ComputeJA4S computes the JA4S fingerprint for a TLS ServerHello.
func ComputeJA4S(data *ServerHelloData) string {
	return fmt.Sprintf("%s_%04x_%s", computeJA4Sa(data), data.CipherSuite, computeJA4Sc(data.Extensions))
}

func computeJA4Sa(data *ServerHelloData) string {
	protocol := "t"
	if data.IsQUIC {
		protocol = "q"
	}

	alpnFirst := "0"
	alpnLast := "0"
	if data.ALPN != "" {
		first := data.ALPN[0]
		if (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9') {
			alpnFirst = string(first)
			alpnLast = string(data.ALPN[len(data.ALPN)-1])
		} else {
			alpnFirst = "9"
			alpnLast = "9"
		}
	}

	return fmt.Sprintf("%s%s%02d%s%s", protocol, tlsVersion(data.Version, data.SupportedVers), min(nonGreaseCount(data.Extensions), 99), alpnFirst, alpnLast)
}

func computeJA4Sc(extensions []uint16) string {
	hexValues := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		if extension != extensionSNI && extension != extensionALPN {
			hexValues = append(hexValues, fmt.Sprintf("%04x", extension))
		}
	}
	if len(hexValues) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(strings.Join(hexValues, ","))
}

func nonGreaseCount(values []uint16) int {
	count := 0
	for _, value := range values {
		if value&0x0f0f != 0x0a0a || byte(value>>8) != byte(value) {
			count++
		}
	}
	return count
}

func tlsVersion(version, supportedVersion uint16) string {
	if supportedVersion == 0x0304 {
		return "13"
	}
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// ValidateJA4S checks whether a JA4S fingerprint has the expected shape.
func ValidateJA4S(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	return len(parts) == 3 && len(parts[0]) == 7 && len(parts[1]) == 4 && len(parts[2]) == 12
}
