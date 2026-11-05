package utils

import (
	"fmt"
	"io"
	"os"
	"testing"
)

func TestRedirectedProgressHasNewlinesAndNoScreenEscapes(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	ClearScreen()
	fmt.Fprint(os.Stdout, "first")
	ClearLine()
	fmt.Fprint(os.Stdout, "second")
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "first\nsecond" {
		t.Fatalf("redirected progress: %q %v", b, err)
	}
}
