package packet

import (
	"testing"
)

func TestDecodeIPFromHex(t *testing.T) {
	ip := []byte("ac1f4076")
	res := parseHexIPv4(ip)
	if res != "172.31.64.118" {
		t.Fatal("unexpected result: ", res, " expected: ", "172.31.64.118")
	}
}

func TestFormatMAC(t *testing.T) {
	res := formatHexMac([]byte("02a36a4e8158"))
	if res != "02:a3:6a:4e:81:58" {
		t.Fatal("unexpected result: ", res, " expected: ", "02:a3:6a:4e:81:58")
	}
}
