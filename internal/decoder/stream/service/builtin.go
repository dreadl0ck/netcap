package service

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
)

// Protocol greetings are independently parsed when optional probe data is absent.
func identifyBuiltinBanner(serv *service, banner []byte) bool {
	if len(banner) > 8192 {
		banner = banner[:8192]
	}
	line, _, ok := bytes.Cut(banner, []byte("\r\n"))
	if !ok {
		return false
	}
	for _, b := range line {
		if b < 32 || b > 126 {
			return false
		}
	}
	s := string(line)
	if strings.HasPrefix(s, "SSH-2.0-") || strings.HasPrefix(s, "SSH-1.99-") {
		parts := strings.Fields(strings.SplitN(s, "-", 3)[2])
		if len(parts) == 0 {
			return false
		}
		serv.Name = "ssh"
		serv.Product, serv.Version, _ = strings.Cut(parts[0], "_")
		return true
	}
	if strings.HasPrefix(s, "HTTP/1.0 ") || strings.HasPrefix(s, "HTTP/1.1 ") {
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(banner)), nil)
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		serv.Name = "http"
		serv.Product = response.Header.Get("Server")
		return true
	}
	if strings.HasPrefix(s, "220 ") {
		words := strings.Fields(strings.ToUpper(s[4:]))
		for _, word := range words {
			if word == "ESMTP" || word == "SMTP" {
				serv.Name = "smtp"
				return true
			}
			if word == "FTP" {
				serv.Name = "ftp"
				return true
			}
		}
	}
	return false
}
