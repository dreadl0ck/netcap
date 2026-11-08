package main

import (
	"encoding/json"
	"flag"
	"github.com/dreadl0ck/netcap/internal/webtech/publication"
	"github.com/dreadl0ck/netcap/internal/webtech/testfixture"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", "", "existing staging directory")
	fixture := flag.String("test-fixture", "", "write synthetic signed integration fixture")
	flag.Parse()
	if *fixture != "" {
		f, err := testfixture.Build()
		if err != nil {
			panic(err)
		}
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			panic(err)
		}
		if err = os.WriteFile(*fixture, append(b, '\n'), 0600); err != nil {
			panic(err)
		}
		return
	}
	if *out == "" {
		panic("provide -out or -test-fixture")
	}
	members, err := publication.Members()
	if err != nil {
		panic(err)
	}
	for name, b := range members {
		if err = os.WriteFile(filepath.Join(*out, name), b, 0600); err != nil {
			panic(err)
		}
	}
}
