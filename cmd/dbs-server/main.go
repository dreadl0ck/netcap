package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dreadl0ck/netcap/internal/dbs"
)

func main() {
	mode := flag.String("mode", "serve", "serve, candidate, or pack")
	root := flag.String("root", "", "candidate root or candidate directory")
	output := flag.String("output", "", "published v3 directory")
	addr := flag.String("addr", ":8080", "listen address")
	year := flag.Int("start-year", 2002, "first required NVD year")
	registry := flag.String("approvals", os.Getenv("NC_DBS_APPROVALS"), "reviewed source registry")
	pin := flag.String("approvals-sha256", os.Getenv("NC_DBS_APPROVALS_SHA256"), "independently pinned registry SHA-256")
	flag.Parse()
	var err error
	switch *mode {
	case "candidate":
		if *root == "" {
			log.Fatal("-root is required")
		}
		var dir string
		dir, err = dbs.BuildCandidate(*root, *year)
		if err == nil {
			fmt.Println(dir)
		}
	case "pack":
		if *root == "" || *output == "" {
			log.Fatal("-root and -output are required")
		}
		_, err = dbs.PackV3WithRegistry(*root, *output, *registry, *pin)
	case "serve":
		err = dbs.NewDBServerWithRegistry(*addr, *year, true, *registry, *pin).Start()
	default:
		log.Fatalf("unsupported mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}
