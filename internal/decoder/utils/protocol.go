package utils

import "strings"

func CanonicalProtocol(name string) string {
	switch strings.ToLower(name) {
	case "http", "http1", "http/1.0", "http/1.1":
		return "HTTP"
	case "http2", "http/2", "http/2.0":
		return "HTTP/2"
	case "https":
		return "HTTPS"
	case "tls", "ssl":
		return "TLS"
	case "dns":
		return "DNS"
	case "ssh":
		return "SSH"
	case "ftp":
		return "FTP"
	}
	return name
}
