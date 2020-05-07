package encoder

import (
	"strings"
	"testing"
	"time"
)

func TestFTPCredentialsHarvester(t *testing.T) {
	data := []byte(`220 ProFTPD 1.3.0a Server (ProFTPD Anonymous Server) [192.168.1.231]
USER ftpUser
331 Anonymous login ok, send your complete email address as your password.
PASS ftpPass
230 Anonymous access granted, restrictions apply.
SYST
215 UNIX Type: L8
FEAT
211-Features:
MDTM
REST STREAM
SIZE
211 End
PWD
257 "/" is current directory.
EPSV
229 Entering Extended Passive Mode (|||58612|)
LIST
150 Opening ASCII mode data connection for file list
226 Transfer complete.
TYPE I
200 Type set to I
SIZE resume.doc
213 39424
EPSV`)
	finalData := strings.ReplaceAll(string(data), "\n", "\r\n")

	c := ftpHarvester([]byte(finalData), "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found")
	}

	if c.User != "ftpUser" {
		t.Fatal("incorrect pass, got:", c.User, "expected: ftpUser")
	}

	if c.Password != "ftpPass" {
		t.Fatal("incorrect pass, got:", c.Password, "expected: ftpPass")
	}

}
