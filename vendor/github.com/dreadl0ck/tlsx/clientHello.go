package tlsx

import "fmt"

const (
	ClientHelloRandomLen = 32
)

type ClientHello struct {
	TLSMessage
	HandshakeType    uint8
	HandshakeLen     uint32
	HandshakeVersion Version
	Random           []byte
	SessionIDLen     uint32
	SessionID        []byte
	CipherSuiteLen   uint16
	CipherSuites     []CipherSuite
	CompressMethods  []uint8
	ExtensionLen     uint16
	Extensions       map[Extension]uint16 // [Type]Length
	SNI              string
	SignatureAlgs    []uint16
	SupportedGroups  []uint16
	SupportedPoints  []uint8
	OSCP             bool
	ALPNs            []string
	AllExtensions    []uint16
}

func (ch ClientHello) String() string {
	str := fmt.Sprintln("Version:", ch.Version)
	str += fmt.Sprintln("Handshake Type:", ch.HandshakeType)
	str += fmt.Sprintln("Handshake Version:", ch.HandshakeVersion)
	str += fmt.Sprintf("SessionID: %#v\n", ch.SessionID)
	str += fmt.Sprintf("Cipher Suites (%d): %v\n", ch.CipherSuiteLen, ch.CipherSuites)
	str += fmt.Sprintf("Compression Methods: %v\n", ch.CompressMethods)
	str += fmt.Sprintln("Extensions:", ch.Extensions)
	str += fmt.Sprintf("SNI: %q\n", ch.SNI)
	str += fmt.Sprintf("Signature Algorithms: %#v\n", ch.SignatureAlgs)
	str += fmt.Sprintf("Groups: %#v\n", ch.SupportedGroups)
	str += fmt.Sprintf("Points: %#v\n", ch.SupportedPoints)
	str += fmt.Sprintf("OSCP: %v\n", ch.OSCP)
	str += fmt.Sprintf("ALPNs: %v", ch.ALPNs)
	return str
}

func (ch *ClientHello) Unmarshall(payload []byte) error {
	ch.Raw = payload
	ch.Type = uint8(payload[0])
	ch.Version = Version(payload[1])<<8 | Version(payload[2])
	ch.MessageLen = uint16(payload[3])<<8 | uint16(payload[4])

	if ch.Type != uint8(22) {
		return ErrHandshakeWrongType
	}

	hs := payload[5:]

	if len(hs) < 6 {
		return ErrHandshakeBadLength
	}

	ch.HandshakeType = uint8(hs[0])

	if ch.HandshakeType != 1 {
		return ErrHandshakeWrongType
	}
	ch.HandshakeLen = uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3])
	ch.HandshakeVersion = Version(hs[4])<<8 | Version(hs[5])

	hs = hs[6:]

	if len(hs) < ClientHelloRandomLen {
		return ErrHandshakeBadLength
	}

	// Get random data
	ch.Random = hs[:ClientHelloRandomLen]

	hs = hs[ClientHelloRandomLen:]

	if len(hs) < 1 {
		return ErrHandshakeBadLength
	}

	// Get SessionID
	ch.SessionIDLen = uint32(hs[0])
	hs = hs[1:]

	if len(hs) < int(ch.SessionIDLen) {
		return ErrHandshakeBadLength
	}

	if ch.SessionIDLen != 0 {
		ch.SessionID = hs[:ch.SessionIDLen]
	}

	hs = hs[ch.SessionIDLen:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// Cipher Suite
	ch.CipherSuiteLen = uint16(hs[0])<<8 | uint16(hs[1])

	numCiphers := ch.CipherSuiteLen / 2

	if len(hs) < int(ch.CipherSuiteLen) {
		return ErrHandshakeBadLength
	}

	ch.CipherSuites = make([]CipherSuite, numCiphers)
	for i := 0; i < int(numCiphers); i++ {
		ch.CipherSuites[i] = CipherSuite(hs[2+2*i])<<8 | CipherSuite(hs[3+2*i])
	}

	hs = hs[2+ch.CipherSuiteLen:]

	if len(hs) < 1 {
		return ErrHandshakeBadLength
	}

	// Compression Methods
	numCompressMethods := int(hs[0])

	if len(hs) < 1+numCompressMethods {
		return ErrHandshakeBadLength
	}

	ch.CompressMethods = make([]uint8, numCompressMethods)
	for i := 0; i < int(numCompressMethods); i++ {
		ch.CompressMethods[i] = uint8(hs[1+1*i])
	}

	hs = hs[1+numCompressMethods:]

	if len(hs) < 2 {
		// No extensions or malformed length
		return ErrHandshakeBadLength
	}

	// Extensions
	ch.ExtensionLen = uint16(hs[0])<<8 | uint16(hs[1])

	if len(hs) < int(ch.ExtensionLen) {
		return ErrHandshakeExtBadLength
	}

	hs = hs[2:]
	ch.Extensions = make(map[Extension]uint16)

	for len(hs) > 0 {
		if len(hs) < 4 {
			return ErrHandshakeExtBadLength
		}

		extType := Extension(hs[0])<<8 | Extension(hs[1])
		length := uint16(hs[2])<<8 | uint16(hs[3])

		if len(hs) < 4+int(length) {
			return ErrHandshakeExtBadLength
		}

		data := hs[4 : 4+length]
		hs = hs[4+length:]

		ch.AllExtensions = append(ch.AllExtensions, uint16(extType))

		switch extType {
		case ExtServerName:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}
			sniLen := int(data[0])<<8 | int(data[0])

			data = data[2:]

			if len(data) < sniLen {
				// Malformed SNI data
				return ErrHandshakeExtBadLength
			}

			for len(data) > 0 {
				nameType := data[0]

				if len(data) < 3 {
					// Malformed ServerName
					return ErrHandshakeExtBadLength
				}

				nameLen := int(data[1])<<8 | int(data[2])

				data = data[3:]

				switch nameType {
				case SNINameTypeDNS:
					ch.SNI = string(data)
				default:
					// Unknown Name Type
				}
				data = data[nameLen:]
			}
		case ExtSignatureAlgs:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}
			sigLen := int(data[0])<<8 | int(data[1])

			data = data[2:]

			if len(data) < sigLen {
				return ErrHandshakeExtBadLength
			}

			ch.SignatureAlgs = make([]uint16, sigLen/2)

			for i := 0; i < sigLen/2; i++ {
				ch.SignatureAlgs[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
			}
		case ExtSupportedGroups:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}
			groupLen := int(data[0])<<8 | int(data[1])

			data = data[2:]

			if len(data) < groupLen {
				// Malformed length
				return ErrHandshakeExtBadLength
			}

			ch.SupportedGroups = make([]uint16, groupLen/2)
			for i := 0; i < groupLen/2; i++ {
				ch.SupportedGroups[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
			}
		case ExtECPointFormats:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}
			pointLen := int(data[0])

			data = data[1:]

			if len(data) < pointLen {
				return ErrHandshakeExtBadLength
			}

			ch.SupportedPoints = make([]uint8, pointLen)
			for i := 0; i < pointLen; i++ {
				ch.SupportedPoints[i] = uint8(data[i])
			}

		case ExtStatusRequest:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}

			switch data[0] {
			case OCSPStatusRequest:
				ch.OSCP = true
			}
		case ExtALPN:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}

			alpnLen := int(data[0])<<8 | int(data[1])
			data = data[2:]

			if len(data) != alpnLen {
				return ErrHandshakeExtBadLength
			}

			for len(data) > 0 {
				stringLen := int(data[0])
				data = data[1:]
				ch.ALPNs = append(ch.ALPNs, string(data[:stringLen]))
				data = data[stringLen:]
			}
		default:
			// Other extension where we only care about presence, or presence
			// and length or unknown extension
			ch.Extensions[extType] = length
		}

	}

	return nil
}
