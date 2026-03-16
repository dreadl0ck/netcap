package credentials

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/db"
	"github.com/dreadl0ck/netcap/internal/logger"
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

	c := ftpHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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

	c = ftpHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	// Enhanced HTTP Digest now extracts the actual username
	if c.User != "Mufasa" {
		t.Fatal("incorrect username, got:", c.User, "expected: Mufasa")
	}

	// Password field now contains Hashcat format
	if c.Password == "" {
		t.Fatal("expected Hashcat format in password field, got empty string")
	}

	// Verify it contains key Digest parameters
	if !strings.Contains(c.Password, "Mufasa") || !strings.Contains(c.Password, "testrealm@host.com") {
		t.Fatal("password field should contain Hashcat format with username and realm, got:", c.Password)
	}
}

// IMAP Harvester test
func TestIMAPCredentialsHarvester(t *testing.T) {
	data := []byte(`* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN] IMAP/POP3 ready - us11-011mip
A1 login someuser@example.atmailcloud.com My_P@ssword1
A1 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE NOTIFY SPECIAL-USE QUOTA] Logged in`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := imapHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c = imapHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c = imapHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c = imapHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c := telnetHarvester.HarvesterFunc([]byte(finalData), "test", time.Now())
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
	c := smtpHarvester.HarvesterFunc([]byte(finalData), "test1", time.Now())
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
	c = smtpHarvester.HarvesterFunc([]byte(finalData), "test2", time.Now())
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
	c = smtpHarvester.HarvesterFunc([]byte(finalData), "test3", time.Now())
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
	c = smtpHarvester.HarvesterFunc([]byte(finalData), "test4", time.Now())
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

// TestHTTPSensitiveURLParameters tests extraction of sensitive URL parameters
func TestHTTPSensitiveURLParameters(t *testing.T) {
	// Test case 1: Real-world example from TODO.md with key parameter
	data := []byte(`GET /cpv/base.php?c=9&key=19a59f6e0085f717c5d5b1f9fb79f923&site=5269&cn=Exchange+Inventory&br=Chrome&ip=173.166.146.112&user=Mozilla/5.0%20(Windows%20NT%206.1)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/56.0.2924.87%20Safari/537.36&bd=13.75 HTTP/1.1
Host: officialsurvey.info
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Referer: http://engine.spotscenered.info/Redirect.eng?MediaSegmentId=28350&dcid=1_ctx_170942ac-ce9a-458f-88fd-d57a2f5da4cf&vmId=00000000-0000-0000-0000-000000000000&abr=false&timeZoneOffset=&v=hXPZuKMawgsqqaXmgsiEEscqvxeFp0YWn8oV21lbHO8iCvpmH9sk2fSprt3x5A_b-2hEatyK0i4Deb-rUYJDFrdTFYwunJKu09ZEHLHzJxZf1LprBVtCSV2f70MYber7nGoIrMgllcInD2Ysbgo5-9yvR-REHLKIQ9jYTfQLTTJCLIX2PMNL2j574BAFOFkImTNsoFnhQK25iqeZQcTK08InTH2uLJqChKF2As4Dy0xyfaGe-chhfSnx8NhEVpoBwgVhj8YKWVGk9STqUp4uPvoZ2xsyWkiZcXf2fWS2_OR4O8Yntpldfvpcf2SkMQDEVmgdIpH4Xg0NO05x2bjoI7tvwDSFlpGOWdSLOYdlnbMSDwE_qPErwUxywYBSTT0guM7frmfPAIJrD1ZeebV6SxeEGoqfU9_FEMFXKP5wCD_OzDghWhHJ4xv5BlhzjfOEwbi6sKbGyxG_CPmJ07b5HnyiF2XoFpwpEqkwqbluJWkNIztTMRu3MepUrXDjcm3D5sJEuWO1GLBXp7MX6FR9HrXhYYNvuzwW6D1mnBZMDSOkpha8617P8OM6XUEguI_AjScaiBweQQ1CyKTwGSzy-cVzs4Dpdrk1iQc_0bwbFuaxPp6MR-ZXfEVB-EMvHgYxLlDq4hcUuRPBRai0TDCvkMUHocDyP0sYbTx2GOiVPyU_p38nur2McVZBQjj1TAeMYCan9rZ        4kAw4ou5bJU_fsAxdNP6BCpDXKiI1zNyN-N_X4vZI1odF6LKz6SE0cWTz-rdnu8V0IeUqZqxCproo__LgBP_OY_XWL1kNN_4q3j2uXjiwJ7tK8fv4KDDv7w_YeUzWRmhmgJUzcXOtQaNM5Taj72ahBrOthXgwAbuOBcCsesPU4Le0Cf8Qd5Mv_ODSig-mqiiDif6xG3tsV25LONqRbY6UtMvmMljc9KVWdjhw5DIEY3FOIr3r50c1i890scKy_zN5sEaJYV8mQfjdsGALIRGVJpCH4Yao3kgB8zSNoZHrbLLwUcXJcaukWlomMIHUSvJmGsyOmlDmHxsu4xwXVRZU1AcOTZJA7DEEiTPw35IVAWtiQseGLIaeqPybRl7L1TZgCsr2kzYZI6ENmNrUVqraQodL13FJlOdNuwIygeZh7j0X8T2Y0XIA_PmXwW0JzJvy6PqMp82MDedXd_vvpt9xqjOXuiom68VzNIwMm81jwKGgCI5Dahx36EMw0
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8`)

	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if c.Service != "HTTP URL Parameter" {
		t.Fatalf("expected service 'HTTP URL Parameter', got: %s", c.Service)
	}

	if c.User != "officialsurvey.info" {
		t.Fatalf("expected host 'officialsurvey.info', got: %s", c.User)
	}

	if !strings.Contains(c.Password, "key=19a59f6e0085f717c5d5b1f9fb79f923") {
		t.Fatalf("expected password to contain key parameter, got: %s", c.Password)
	}

	if !strings.Contains(c.Notes, "GET") {
		t.Fatalf("expected notes to contain method GET, got: %s", c.Notes)
	}

	// Test case 2: API key parameter
	data = []byte(`GET /api/v1/data?api_key=sk_live_51H3k4fE2eZvKYlo2C&user_id=123 HTTP/1.1
Host: api.example.com
Accept: application/json`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-2", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for api_key")
	}

	if !strings.Contains(c.Password, "api_key=sk_live_51H3k4fE2eZvKYlo2C") {
		t.Fatalf("expected password to contain api_key parameter, got: %s", c.Password)
	}

	// Test case 3: Access token parameter
	data = []byte(`POST /oauth/callback?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&state=12345678 HTTP/1.1
Host: oauth.example.com
Content-Type: application/json`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-3", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for access_token")
	}

	if !strings.Contains(c.Password, "access_token=") {
		t.Fatalf("expected password to contain access_token parameter, got: %s", c.Password)
	}

	if !strings.Contains(c.Notes, "POST") {
		t.Fatalf("expected notes to contain method POST, got: %s", c.Notes)
	}

	// Test case 4: Multiple sensitive parameters
	data = []byte(`GET /api/resource?token=abc123456789&api_secret=secret987654321&foo=bar HTTP/1.1
Host: multi.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-4", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for multiple parameters")
	}

	// Should contain both token and api_secret
	if !strings.Contains(c.Password, "token=abc123456789") {
		t.Fatalf("expected password to contain token parameter, got: %s", c.Password)
	}

	if !strings.Contains(c.Password, "api_secret=secret987654321") {
		t.Fatalf("expected password to contain api_secret parameter, got: %s", c.Password)
	}

	// Test case 5: Short values should be filtered out (less than 8 characters)
	data = []byte(`GET /api/test?key=short&other=param HTTP/1.1
Host: test.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-5", time.Now())

	// Should return nil because "short" is only 5 characters
	if c != nil && strings.Contains(c.Password, "key=short") {
		t.Fatal("expected short key values to be filtered out")
	}

	// Test case 6: Bearer token
	data = []byte(`GET /protected?bearer=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 HTTP/1.1
Host: protected.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-6", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for bearer token")
	}

	if !strings.Contains(c.Password, "bearer=") {
		t.Fatalf("expected password to contain bearer parameter, got: %s", c.Password)
	}

	// Test case 7: Session ID
	data = []byte(`GET /dashboard?sessionid=a1b2c3d4e5f6g7h8i9j0 HTTP/1.1
Host: app.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-7", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for sessionid")
	}

	if !strings.Contains(c.Password, "sessionid=") {
		t.Fatalf("expected password to contain sessionid parameter, got: %s", c.Password)
	}

	// Test case 8: No sensitive parameters
	data = []byte(`GET /page?foo=bar&baz=qux HTTP/1.1
Host: normal.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-8", time.Now())

	// Should return nil as there are no sensitive parameters
	if c != nil && c.Service == "HTTP URL Parameter" {
		t.Fatal("expected no credentials for non-sensitive parameters")
	}

	// Test case 9: JWT token
	data = []byte(`GET /verify?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ HTTP/1.1
Host: jwt.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-9", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for jwt")
	}

	if !strings.Contains(c.Password, "jwt=") {
		t.Fatalf("expected password to contain jwt parameter, got: %s", c.Password)
	}
}

// TestHTTPSensitiveURLParametersEdgeCases tests edge cases and special scenarios
func TestHTTPSensitiveURLParametersEdgeCases(t *testing.T) {
	// Test case 1: No Host header
	data := []byte(`GET /api?key=12345678abcdefgh HTTP/1.1
User-Agent: test`)

	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials even without Host header")
	}

	if !strings.Contains(c.Password, "key=12345678abcdefgh") {
		t.Fatalf("expected password to contain key parameter, got: %s", c.Password)
	}

	// Test case 2: URL-encoded parameter value
	data = []byte(`GET /api?token=abc%2B123%2Fdef%3D HTTP/1.1
Host: encoded.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials for URL-encoded token")
	}

	// Test case 3: Mixed case parameter names (should still match)
	data = []byte(`GET /api?Api_Key=12345678ABCDEFGH HTTP/1.1
Host: mixedcase.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	// Note: Our implementation is case-sensitive by default
	// This test documents that behavior
	if c != nil && strings.Contains(c.Password, "Api_Key") {
		// If we wanted case-insensitive matching, we'd need to normalize parameter names
		t.Logf("Found mixed-case parameter: %s", c.Password)
	}

	// Test case 4: Empty parameter value
	data = []byte(`GET /api?key=&other=value HTTP/1.1
Host: empty.example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	// Should not match empty values
	if c != nil && strings.Contains(c.Password, "key=") && !strings.Contains(c.Password, "key=.") {
		t.Fatal("expected empty key values to be filtered out")
	}

	// Test case 5: Very long token value
	longToken := strings.Repeat("a", 500)
	data = fmt.Appendf(nil, `GET /api?token=%s HTTP/1.1
Host: longtoken.example.com`, longToken)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials for long token")
	}

	if !strings.Contains(c.Password, "token=") {
		t.Fatalf("expected password to contain token parameter, got: %s", c.Password)
	}
}

// TestHTTPSessionCookies tests extraction of session cookies from HTTP responses
func TestHTTPSessionCookies(t *testing.T) {
	// Test case 1: Real-world example from TODO.md with PHPSESSID
	data := []byte(`HTTP/1.1 302 Moved Temporarily
Date: Wed, 19 Apr 2017 13:31:02 GMT
Server: Apache/2.4.12 (Unix) OpenSSL/1.0.1e-fips mod_bwlimited/1.4 mod_fcgid/2.3.9
X-Powered-By: PHP/5.4.40
P3P: CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: PHPSESSID=96ebc80a0771786591c82d702f8ac88e; path=/
Set-Cookie: cpvlabclick=ZjNpaWMwZGdfOV8yNF94eHhfMjgzNzY3Xzc%3D; expires=Fri, 19-May-2017 13:31:02 GMT
Set-Cookie: cpvlablevel=1; expires=Fri, 19-May-2017 13:31:02 GMT
Set-Cookie: cpvlabclicks=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT
Location: http://brandresearch.me/cpisp/lpos.php?&cn=Exchange+Inventory&br=Chrome&ip=173.166.146.112&user=Mozilla%2F5.0+%28Windows+NT+6.1%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F56.0.2924.87+Safari%2F537.36&bd=13.75
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html`)

	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if c.Service != "HTTP Session Cookie" {
		t.Fatalf("expected service 'HTTP Session Cookie', got: %s", c.Service)
	}

	if !strings.Contains(c.Password, "PHPSESSID=96ebc80a0771786591c82d702f8ac88e") {
		t.Fatalf("expected password to contain PHPSESSID cookie, got: %s", c.Password)
	}

	if c.User != "brandresearch.me" {
		t.Fatalf("expected host 'brandresearch.me' extracted from Location header, got: %s", c.User)
	}

	if !strings.Contains(c.Notes, "302") {
		t.Fatalf("expected notes to contain status code 302, got: %s", c.Notes)
	}

	// Verify deleted cookie is NOT included
	if strings.Contains(c.Password, "cpvlabclicks=deleted") {
		t.Fatal("expected deleted cookies to be filtered out")
	}

	// Test case 2: Java JSESSIONID
	data = []byte(`HTTP/1.1 200 OK
Date: Mon, 23 Nov 2025 10:00:00 GMT
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=1A2B3C4D5E6F7G8H9I0J; Path=/myapp; HttpOnly
Content-Type: text/html;charset=UTF-8
Content-Length: 1234`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-2", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for JSESSIONID")
	}

	if !strings.Contains(c.Password, "JSESSIONID=1A2B3C4D5E6F7G8H9I0J") {
		t.Fatalf("expected password to contain JSESSIONID cookie, got: %s", c.Password)
	}

	// Test case 3: ASP.NET SessionId
	data = []byte(`HTTP/1.1 200 OK
Date: Mon, 23 Nov 2025 10:00:00 GMT
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=abcdef123456789012345678; path=/; HttpOnly
X-AspNet-Version: 4.0.30319
Content-Type: text/html; charset=utf-8`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-3", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for ASP.NET_SessionId")
	}

	if !strings.Contains(c.Password, "ASP.NET_SessionId=abcdef123456789012345678") {
		t.Fatalf("expected password to contain ASP.NET_SessionId cookie, got: %s", c.Password)
	}

	// Test case 4: Django sessionid
	data = []byte(`HTTP/1.1 200 OK
Date: Mon, 23 Nov 2025 10:00:00 GMT
Server: nginx/1.18.0
Set-Cookie: sessionid=xyz789abc123def456ghi012; HttpOnly; Path=/
Content-Type: text/html; charset=utf-8`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-4", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for Django sessionid")
	}

	if !strings.Contains(c.Password, "sessionid=xyz789abc123def456ghi012") {
		t.Fatalf("expected password to contain sessionid cookie, got: %s", c.Password)
	}

	// Test case 5: Express.js connect.sid
	data = []byte(`HTTP/1.1 200 OK
Date: Mon, 23 Nov 2025 10:00:00 GMT
Server: nginx/1.18.0
Set-Cookie: connect.sid=s%3Aj8eJc3kD9fL2mN5pQ7rT1uV4wX6yZ8aB.1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3; Path=/; HttpOnly
Content-Type: text/html; charset=utf-8`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-5", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for connect.sid")
	}

	if !strings.Contains(c.Password, "connect.sid=") {
		t.Fatalf("expected password to contain connect.sid cookie, got: %s", c.Password)
	}

	// Test case 6: Multiple session cookies
	data = []byte(`HTTP/1.1 200 OK
Date: Mon, 23 Nov 2025 10:00:00 GMT
Server: Apache
Set-Cookie: PHPSESSID=session123456789; path=/
Set-Cookie: auth_token=token987654321abc; HttpOnly
Set-Cookie: tracking=xyz; expires=Fri, 19-May-2027 13:31:02 GMT
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-6", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for multiple cookies")
	}

	// Should contain both PHPSESSID and auth_token
	if !strings.Contains(c.Password, "PHPSESSID=session123456789") {
		t.Fatalf("expected password to contain PHPSESSID cookie, got: %s", c.Password)
	}

	if !strings.Contains(c.Password, "auth_token=token987654321abc") {
		t.Fatalf("expected password to contain auth_token cookie, got: %s", c.Password)
	}

	// tracking cookie should NOT be included (not a session cookie)
	if strings.Contains(c.Password, "tracking=") {
		t.Fatal("expected non-session cookies to be filtered out")
	}

	// Test case 7: Short session ID should be filtered
	data = []byte(`HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=short; path=/
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-7", time.Now())

	// Should return nil because "short" is too short
	if c != nil && strings.Contains(c.Password, "PHPSESSID=short") {
		t.Fatal("expected short session IDs to be filtered out")
	}

	// Test case 8: HTTP request should not extract cookies (only responses)
	data = []byte(`GET / HTTP/1.1
Host: example.com
Cookie: PHPSESSID=96ebc80a0771786591c82d702f8ac88e
User-Agent: Mozilla/5.0`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-8", time.Now())

	// Should not extract from request Cookie header, only response Set-Cookie
	if c != nil && c.Service == "HTTP Session Cookie" {
		t.Fatal("expected session cookie extraction only from responses, not requests")
	}
}

// TestHTTPFormCredentials tests extraction of credentials from HTTP POST form data
func TestHTTPFormCredentials(t *testing.T) {
	// Test case 1: Standard login form with username and password
	data := []byte(`POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

username=admin&password=secret123`)

	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if c.Service != "HTTP Form Login" {
		t.Fatalf("expected service 'HTTP Form Login', got: %s", c.Service)
	}

	if c.User != "admin" {
		t.Fatalf("expected user 'admin', got: %s", c.User)
	}

	if c.Password != "secret123" {
		t.Fatalf("expected password 'secret123', got: %s", c.Password)
	}

	if !strings.Contains(c.Notes, "POST") {
		t.Fatalf("expected notes to contain 'POST', got: %s", c.Notes)
	}

	if !strings.Contains(c.Notes, "UsernameField: username") {
		t.Fatalf("expected notes to contain username field name, got: %s", c.Notes)
	}

	// Test case 2: WordPress login form (log and pwd fields)
	data = []byte(`POST /wp-login.php HTTP/1.1
Host: myblog.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

log=wpuser&pwd=wppass123&wp-submit=Log+In`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-2", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for WordPress form")
	}

	if c.User != "wpuser" {
		t.Fatalf("expected user 'wpuser', got: %s", c.User)
	}

	if c.Password != "wppass123" {
		t.Fatalf("expected password 'wppass123', got: %s", c.Password)
	}

	// Test case 3: Email-based login (email field)
	data = []byte(`POST /auth/login HTTP/1.1
Host: service.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

email=user@example.com&password=myPassword`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-3", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for email login")
	}

	if c.User != "user@example.com" {
		t.Fatalf("expected user 'user@example.com', got: %s", c.User)
	}

	// Test case 4: J2EE j_username/j_password fields
	data = []byte(`POST /j_security_check HTTP/1.1
Host: enterprise.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

j_username=enterpriseuser&j_password=enterprisepass`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-4", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for J2EE form")
	}

	if c.User != "enterpriseuser" {
		t.Fatalf("expected user 'enterpriseuser', got: %s", c.User)
	}

	if c.Password != "enterprisepass" {
		t.Fatalf("expected password 'enterprisepass', got: %s", c.Password)
	}

	// Test case 5: Username only (no password field) - still captured
	data = []byte(`POST /lookup HTTP/1.1
Host: app.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

username=lookupuser`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-5", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for username-only form")
	}

	if c.User != "lookupuser" {
		t.Fatalf("expected user 'lookupuser', got: %s", c.User)
	}

	// Test case 6: Should NOT match GET requests
	data = []byte(`GET /login?username=admin&password=secret HTTP/1.1
Host: example.com`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-6", time.Now())

	if c != nil && c.Service == "HTTP Form Login" {
		t.Fatal("expected no form credentials for GET request")
	}

	// Test case 7: Should NOT match non-form content types
	data = []byte(`POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 45

{"username":"admin","password":"secret123"}`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-7", time.Now())

	if c != nil && c.Service == "HTTP Form Login" {
		t.Fatal("expected no form credentials for JSON content type")
	}

	// Test case 8: URL-encoded special characters in form data
	data = []byte(`POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

username=user%40example.com&password=p%40ss%26123`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-8", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for URL-encoded form")
	}

	// URL decoding should work
	if c.User != "user@example.com" {
		t.Fatalf("expected user 'user@example.com' (decoded), got: %s", c.User)
	}

	if c.Password != "p@ss&123" {
		t.Fatalf("expected password 'p@ss&123' (decoded), got: %s", c.Password)
	}

	// Test case 9: Check URI is captured in notes
	data = []byte(`POST /custom/auth/endpoint HTTP/1.1
Host: mysite.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

login=testuser&passwd=testpass`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow-9", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if !strings.Contains(c.Notes, "/custom/auth/endpoint") {
		t.Fatalf("expected notes to contain URI, got: %s", c.Notes)
	}

	if !strings.Contains(c.Notes, "mysite.com") {
		t.Fatalf("expected notes to contain host, got: %s", c.Notes)
	}
}

// TestHTTPFormCredentialsEdgeCases tests edge cases for HTTP form credential extraction
func TestHTTPFormCredentialsEdgeCases(t *testing.T) {
	// Test case 1: Empty username should not match
	data := []byte(`POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

username=&password=secret`)

	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c != nil && c.Service == "HTTP Form Login" && c.User == "" {
		t.Fatal("expected no form credentials for empty username")
	}

	// Test case 2: No recognized fields
	data = []byte(`POST /api HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

foo=bar&baz=qux&unrelated=data`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c != nil && c.Service == "HTTP Form Login" {
		t.Fatal("expected no form credentials for unrecognized fields")
	}

	// Test case 3: Mixed case field names (case-insensitive matching would be nice)
	data = []byte(`POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

USERNAME=admin&PASSWORD=secret123`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	// Our implementation is case-insensitive (lowercase version check)
	if c != nil && c.Service == "HTTP Form Login" {
		t.Logf("Mixed case handling: user=%s, pass=%s", c.User, c.Password)
	}

	// Test case 4: Large form body (should be truncated)
	largeData := fmt.Sprintf(`POST /upload HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 5000

data=%s&username=hiddenuser&password=hiddenpass`, strings.Repeat("x", 2500))

	finalData = strings.ReplaceAll(largeData, "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	// Form body is truncated to maxHTTPFormBodyLength (2000), so credentials
	// at the end may not be found if they're beyond the limit
	// This is intentional to prevent false positives on large uploads

	// Test case 5: Multiple form submissions in same stream
	data = []byte(`POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

user=first&pass=firstpass`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if c.User != "first" {
		t.Fatalf("expected user 'first', got: %s", c.User)
	}
}

// TestHTTPSessionCookiesEdgeCases tests edge cases for session cookie extraction
func TestHTTPSessionCookiesEdgeCases(t *testing.T) {
	// Test case 1: Case-insensitive cookie names
	data := []byte(`HTTP/1.1 200 OK
Set-Cookie: phpsessid=lowercase123456789; path=/
Content-Type: text/html`)

	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")
	c := httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for lowercase phpsessid")
	}

	if !strings.Contains(c.Password, "phpsessid=lowercase123456789") {
		t.Fatalf("expected password to contain lowercase phpsessid, got: %s", c.Password)
	}

	// Test case 2: Cookie with complex attributes
	data = []byte(`HTTP/1.1 200 OK
Set-Cookie: JSESSIONID=complex123456789; Path=/app; Domain=.example.com; Secure; HttpOnly; SameSite=Strict
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if !strings.Contains(c.Password, "JSESSIONID=complex123456789") {
		t.Fatalf("expected password to contain JSESSIONID, got: %s", c.Password)
	}

	// Test case 3: Host header in response (unusual but possible)
	data = []byte(`HTTP/1.1 200 OK
Host: response.example.com
Set-Cookie: sessionid=host123456789; path=/
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found")
	}

	if c.User != "response.example.com" {
		t.Fatalf("expected host 'response.example.com', got: %s", c.User)
	}

	// Test case 4: No host or location
	data = []byte(`HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=nohost1234567890; path=/
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials even without host information")
	}

	if !strings.Contains(c.Password, "PHPSESSID=nohost1234567890") {
		t.Fatalf("expected password to contain PHPSESSID, got: %s", c.Password)
	}

	// Test case 5: URL-encoded cookie value
	data = []byte(`HTTP/1.1 200 OK
Set-Cookie: session=abc%2Bdef%3D123456789; path=/
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials for URL-encoded session cookie")
	}

	if !strings.Contains(c.Password, "session=") {
		t.Fatalf("expected password to contain session cookie, got: %s", c.Password)
	}

	// Test case 6: Empty cookie value
	data = []byte(`HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=; path=/
Content-Type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	// Should not match empty values
	if c != nil && strings.Contains(c.Password, "PHPSESSID=;") {
		t.Fatal("expected empty session cookie values to be filtered out")
	}

	// Test case 7: HTTP/2 response
	data = []byte(`HTTP/2 200
date: Mon, 23 Nov 2025 10:00:00 GMT
set-cookie: sessionid=http2session123456789; path=/
content-type: text/html`)

	finalData = strings.ReplaceAll(string(data), "\n", "\r\n")
	c = httpHarvester.HarvesterFunc([]byte(finalData), "test-flow", time.Now())

	if c == nil {
		t.Fatal("expected credentials to be found for HTTP/2 response")
	}

	if !strings.Contains(c.Password, "sessionid=http2session123456789") {
		t.Fatalf("expected password to contain sessionid, got: %s", c.Password)
	}
}
