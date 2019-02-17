package tlsx

import "fmt"

type (
	Version uint16 // TLS Record Version, also handshake version
)

// String method to return string of TLS version
func (v Version) String() string {
	if name, ok := VersionReg[v]; ok {
		return name
	}
	return fmt.Sprintf("%#v (unknown)", v)
}

const (
	VerSSL30 Version = 0x300
	VerTLS10 Version = 0x301
	VerTLS11 Version = 0x302
	VerTLS12 Version = 0x303
	VerTLS13 Version = 0x304
)

var VersionReg = map[Version]string{
	VerSSL30: "SSL 3.0",
	VerTLS10: "TLS 1.0",
	VerTLS11: "TLS 1.1",
	VerTLS12: "TLS 1.2",
	VerTLS13: "TLS 1.3",
}
