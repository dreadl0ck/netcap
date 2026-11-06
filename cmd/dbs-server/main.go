package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/dbs"
)

func main() {
	mode := flag.String("mode", "serve", "serve, candidate, pack, keys, approve, or sign")
	root := flag.String("root", "", "candidate root or candidate directory")
	output := flag.String("output", "", "published v3 directory")
	addr := flag.String("addr", ":8080", "listen address")
	year := flag.Int("start-year", 2002, "first required NVD year")
	registry := flag.String("approvals", os.Getenv("NC_DBS_APPROVALS"), "reviewed source registry")
	pin := flag.String("approvals-sha256", os.Getenv("NC_DBS_APPROVALS_SHA256"), "independently pinned registry SHA-256")
	policy := flag.String("policy", "", "reviewed source policy")
	policyPin := flag.String("policy-sha256", "", "independently pinned source policy SHA-256")
	previousCount := flag.Int("previous-count", 0, "previous published NVD count")
	key := flag.String("key", "", "publisher private key")
	certificate := flag.String("certificate", "", "root-signed publisher certificate")
	sequence := flag.Uint64("sequence", 0, "monotonic publication sequence")
	epoch := flag.Uint64("epoch", 0, "replacement signing key epoch")
	signedRoot := flag.String("signed-root", os.Getenv("NC_DBS_SIGNED_ROOT"), "signed publication directory")
	flag.Parse()
	if *signedRoot != "" {
		if err := os.Setenv("NC_DBS_SIGNED_ROOT", *signedRoot); err != nil {
			log.Fatal(err)
		}
	}
	var err error
	switch *mode {
	case "rotate-key":
		err = dbs.RotateSigningKey(*key, *output, *epoch)
	case "keys":
		err = dbs.GenerateSigningKeys(*root)
	case "approve":
		err = dbs.ApproveCandidate(*root, *policy, *policyPin, *registry, *previousCount)
	case "sign":
		var meta dbs.DBMetadata
		var data []byte
		data, err = os.ReadFile(filepath.Join(*output, "latest.json"))
		if err == nil {
			err = json.Unmarshal(data, &meta)
		}
		if err == nil {
			err = dbs.SignPublication(meta, *registry, *policy, *key, *certificate, *output, *sequence)
		}
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
