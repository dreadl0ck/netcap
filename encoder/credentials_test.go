package encoder

import (
	"strings"
	"testing"
	"time"
)

func TestFTPCredentialsHarvester(t *testing.T) {
	data := []byte(`220 (vsFTPd 3.0.3)
USER ftpuser
331 Please specify the password.
PASS ftppass
230 Login successful.
SYST
215 UNIX Type: L8`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")

	c := ftpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "ftpuser" {
		t.Fatal("incorrect pass, got:", c.User, "expected: ftpuser")
	}

	if c.Password != "ftppass" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: ftppass")
	}

}

func TestHTTPCredentialsHarvester(t *testing.T) {
	data := []byte(`GET / HTTP/1.1
Host: 127.0.0.1
Connection: keep-alive
Cache-Control: max-age=0
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/81.0.4044.122 Chrome/81.0.4044.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
If-None-Match: W/"5ea9593d-2aa6"
If-Modified-Since: Wed, 29 Apr 2020 10:38:53 GMT`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpBasicAuthHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "admin" {
		t.Fatal("incorrect pass, got:", c.User, "expected: admin")
	}

	if c.Password != "password" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: password")
	}
}

func TestSMTPCredentialsHarvester(t *testing.T) {
	data := []byte(`220 smtp.server.com Simple Mail Transfer Service Ready
EHLO client.example.com
250-smtp.server.com Hello client.example.com
250-SIZE 1000000
250 AUTH LOGIN PLAIN CRAM-MD5
AUTH PLAIN
334
dGVzdAB0ZXN0ADEyMzQ=
235 2.7.0 Authentication successful`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := smtpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "testtest1234" {
		t.Fatal("incorrect username, got:", c.User, "expected: testtest1234")
	}

	if c.Password != "" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: ")
	}

	data = []byte(`220 smtp.server.com Simple Mail Transfer Service Ready
EHLO client.example.com
250-smtp.server.com Hello client.example.com
250-SIZE 1000000
250 AUTH LOGIN PLAIN CRAM-MD5
AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ= *
235 2.7.0 Authentication successful`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = smtpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "testtest1234" {
		t.Fatal("incorrect username, got:", c.User, "expected: testtest1234")
	}

	if c.Password != "" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: ")
	}

	data = []byte(`220 smtp.server.com Simple Mail Transfer Service Ready
EHLO client.example.com
250-smtp.server.com Hello client.example.com
250-SIZE 1000000
250 AUTH LOGIN PLAIN CRAM-MD5
AUTH LOGIN
334 VXNlcm5hbWU6
dGVzdA==
334 UGFzc3dvcmQ6
dGVzdDEyMzQ=
235 2.7.0 Authentication successful`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = smtpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "test" {
		t.Fatal("incorrect pass, got:", c.User, "expected: test")
	}

	if c.Password != "test1234" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: test1234")
	}

	data = []byte(`220 smtp.server.com Simple Mail Transfer Service Ready
EHLO client.example.com
250-smtp.server.com Hello client.example.com
250-SIZE 1000000
250 AUTH LOGIN PLAIN CRAM-MD5
AUTH CRAM-MD5
334 PDQxOTI5NDIzNDEuMTI4Mjg0NzJAc291cmNlZm91ci5hbmRyZXcuY211LmVkdT4=
cmpzMyBlYzNhNTlmZWQzOTVhYmExZWM2MzY3YzRmNGI0MWFjMA==
235 2.7.0 Authentication successful`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = smtpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "<4192942341.12828472@sourcefour.andrew.cmu.edu>" {
		t.Fatal("incorrect pass, got:", c.User, "expected: <4192942341.12828472@sourcefour.andrew.cmu.edu>")
	}

	if c.Password != "rjs3 ec3a59fed395aba1ec6367c4f4b41ac0" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: rjs3 ec3a59fed395aba1ec6367c4f4b41ac0")
	}
}

func TestTelnetCredentialsHarvester(t *testing.T) {
	data := []byte(`host login: aaddmmiinn
.
Password: password
.
Last login: Sat Mar 21 16:34:17 CET 2020 on tty1
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-51-generic x86_64)`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := smtpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "admin" {
		t.Fatal("incorrect pass, got:", c.User, "expected: admin")
	}

	if c.Password != "password" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: password")
	}
}
