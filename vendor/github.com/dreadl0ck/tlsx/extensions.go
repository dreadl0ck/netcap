package tlsx

import "fmt"

type Extension uint16

// String method for a TLS Extension
// See: http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
func (e Extension) String() string {
	if name, ok := ExtensionReg[e]; ok {
		return name
	}
	return fmt.Sprintf("%#v (unknown)", e)
}

// TLS Extensions http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const (
	ExtServerName           Extension = 0
	ExtMaxFragLen           Extension = 1
	ExtClientCertURL        Extension = 2
	ExtTrustedCAKeys        Extension = 3
	ExtTruncatedHMAC        Extension = 4
	ExtStatusRequest        Extension = 5
	ExtUserMapping          Extension = 6
	ExtClientAuthz          Extension = 7
	ExtServerAuthz          Extension = 8
	ExtCertType             Extension = 9
	ExtSupportedGroups      Extension = 10
	ExtECPointFormats       Extension = 11
	ExtSRP                  Extension = 12
	ExtSignatureAlgs        Extension = 13
	ExtUseSRTP              Extension = 14
	ExtHeartbeat            Extension = 15
	ExtALPN                 Extension = 16 // Replaced NPN
	ExtStatusRequestV2      Extension = 17
	ExtSignedCertTS         Extension = 18 // Certificate Transparency
	ExtClientCertType       Extension = 19
	ExtServerCertType       Extension = 20
	ExtPadding              Extension = 21 // Temp http://www.iana.org/go/draft-ietf-tls-padding
	ExtEncryptThenMAC       Extension = 22
	ExtExtendedMasterSecret Extension = 23
	ExtSessionTicket        Extension = 35
	ExtNPN                  Extension = 13172 // Next Protocol Negotiation not ratified and replaced by ALPN
	ExtRenegotiationInfo    Extension = 65281
)

var ExtensionReg = map[Extension]string{
	ExtServerName:           "server_name",
	ExtMaxFragLen:           "max_fragment_length",
	ExtClientCertURL:        "client_certificate_url",
	ExtTrustedCAKeys:        "trusted_ca_keys",
	ExtTruncatedHMAC:        "truncated_hmac",
	ExtStatusRequest:        "status_request",
	ExtUserMapping:          "user_mapping",
	ExtClientAuthz:          "client_authz",
	ExtServerAuthz:          "server_authz",
	ExtCertType:             "cert_type",
	ExtSupportedGroups:      "supported_groups",
	ExtECPointFormats:       "ec_point_formats",
	ExtSRP:                  "srp",
	ExtSignatureAlgs:        "signature_algorithms",
	ExtUseSRTP:              "use_srtp",
	ExtHeartbeat:            "heartbeat",
	ExtALPN:                 "application_layer_protocol_negotiation",
	ExtStatusRequestV2:      "status_request_v2",
	ExtSignedCertTS:         "signed_certificate_timestamp",
	ExtClientCertType:       "client_certificate_type",
	ExtServerCertType:       "server_certificate_type",
	ExtPadding:              "padding",
	ExtEncryptThenMAC:       "encrypt_then_mac",
	ExtExtendedMasterSecret: "extended_master_secret",
	ExtSessionTicket:        "SessionTicket TLS",
	ExtNPN:                  "next_protocol_negotiation",
	ExtRenegotiationInfo:    "renegotiation_info",
}
