package ipp

import "testing"

func TestBinaryHTTPBodyIsNotPrintingProtocol(t *testing.T) {
	for _, body := range [][]byte{{1, 0, 0, 0, 0, 0, 0, 0}, {2, 0, 0, 0, 0, 0, 0, 0}} {
		server := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\n\r\n"), body...)
		if Decoder.CanDecode([]byte("POST /fakeurl.htm HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), server) {
			t.Fatal("binary C2 response claimed as IPP")
		}
	}
}
