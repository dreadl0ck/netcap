package credentials

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/db"
	"github.com/dreadl0ck/netcap/logger"
)

// init functions in the unit tests do not seem to be called for the compiled program,
// even if this file is not in a *_test package scope.
// So we abuse it here to guarantee the logfile handles are initialized for all tests.
func init() {
	var err error
	credLog, _, err = logger.InitZapLogger("../../tests", "decoder", true)
	if err != nil {
		log.Fatal(err)
	}

	dbLog, _, err := logger.InitZapLogger("../../tests", "db", false)
	if err != nil {
		panic(err)
	}

	db.SetLogger(dbLog)

	// TODO
	//stream.serviceLog, _, err = logger.InitDebugLogger("../../tests", "service", true)
	//if err != nil {
	//	log.Fatal(err)
	//}

	// TODO: sync on exit, move to a central place
}

// FTP Harvester test
func TestFTPCredentialsHarvester(t *testing.T) {
	data := `220 (vsFTPd 3.0.3)
USER ftpuser
331 Please specify the password.
PASS ftppass
230 Login successful.
SYST
215 UNIX Type: L8`

	finalData := strings.ReplaceAll(data, "\n", "\r\n")

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

	data = `220 (vsFTPd 3.0.3)
OPTS UTF8 ON
200 Always in UTF8 mode.
USER root
331 Please specify the password.
PASS test123
230 Login successful.
PORT 145,100,110,132,194,180
200 PORT command successful. Consider using PASV.
NLST
150 Here comes the directory listing.
226 Directory send OK.
QUIT
221 Goodbye.
`

	finalData = strings.ReplaceAll(data, "\n", "\r\n")

	c = ftpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "root" {
		t.Fatal("incorrect pass, got:", c.User, "expected: ftpuser")
	}

	if c.Password != "test123" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: ftppass")
	}
}

// HTTP Harvester test
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
	c := httpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "admin" {
		t.Fatal("incorrect pass, got:", c.User, "expected: admin")
	}

	if c.Password != "password" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: password")
	}

	data = []byte(`GET /dir/index.html HTTP/1.0
Host: localhost
Authorization: Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41"
`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"" {
		t.Fatal("incorrect pass, got:", c.User, "expected: the long digest headers")
	}

	if c.Password != "" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: ")
	}
}

// IMAP Harvester test
func TestIMAPCredentialsHarvester(t *testing.T) {
	data := []byte(`* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN] IMAP/POP3 ready - us11-011mip
A1 login someuser@example.atmailcloud.com My_P@ssword1
A1 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE NOTIFY SPECIAL-USE QUOTA] Logged in`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := imapHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "someuser@example.atmailcloud.com" {
		t.Fatal("incorrect username, got:", c.User, "expected: someuser@example.atmailcloud.com")
	}

	if c.Password != "My_P@ssword1" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: My_P@ssword1")
	}

	data = []byte(`* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN] IMAP/POP3 ready - us11-012mip
a authenticate LOGIN
+ VXNlcm5hbWU6
c29tZXVzZXJAZXhhbXBsZS5hdG1haWxjbG91ZC5jb20=
+ UGFzc3dvcmQ6
TXlfUEBzc3dvcmQx
a OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE NOTIFY SPECIAL-USE QUOTA] Logged in`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = imapHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "someuser@example.atmailcloud.com" {
		t.Fatal("incorrect username, got:", c.User, "expected: someuser@example.atmailcloud.com")
	}

	if c.Password != "My_P@ssword1" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: My_P@ssword1")
	}

	data = []byte(`* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN] IMAP/POP3 ready - zeus
a AUTHENTICATE PLAIN
+
dGlnZXJAemV1cy5wAGFkbWluAGFkbWluMTIzNA==
a OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE NOTIFY SPECIAL-USE QUOTA] Logged in`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = imapHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "tiger@zeus.p | admin" {
		t.Fatal("incorrect pass, got:", c.User, "expected: tiger@zeus.p | admin")
	}

	if c.Password != "admin1234" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: admin1234")
	}

	data = []byte(`* OK IMAP4 Server
A0001 AUTHENTICATE CRAM-MD5
+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+
dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
A0001 OK CRAM authentication successful`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = imapHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "<1896.697170952@postoffice.reston.mci.net>" {
		t.Fatal("incorrect pass, got:", c.User, "expected: <1896.697170952@postoffice.reston.mci.net>")
	}

	if c.Password != "tim b913a602c7eda7a495b4e6e7334d3890" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: tim b913a602c7eda7a495b4e6e7334d3890")
	}
}

// Telnet Harvester test
func TestTelnetCredentialsHarvester(t *testing.T) {
	data := []byte(`host login: aaddmmiinn
.
Password: password
.
Last login: Sat Mar 21 16:34:17 CET 2020 on tty1
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-51-generic x86_64)`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := telnetHarvester([]byte(finalData), "test", time.Now())
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

// SMTP Harvester tests
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
	c := smtpHarvester([]byte(finalData), "test1", time.Now())
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
AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ= *
235 2.7.0 Authentication successful`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = smtpHarvester([]byte(finalData), "test2", time.Now())
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
AUTH LOGIN
334 VXNlcm5hbWU6
dGVzdA==
334 UGFzc3dvcmQ6
dGVzdDEyMzQ=
235 2.7.0 Authentication successful`)
	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = smtpHarvester([]byte(finalData), "test3", time.Now())
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
	c = smtpHarvester([]byte(finalData), "test4", time.Now())
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
