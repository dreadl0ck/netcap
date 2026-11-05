package software

import (
	"github.com/dreadl0ck/netcap/internal/decoder/db"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestHTTPClientAndServerSoftwareHaveDifferentOwners(t *testing.T) {
	r := &types.HTTP{Timestamp: 1, Method: "GET", SrcIP: "10.0.0.2", DstIP: "8.8.8.8", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362", ServerName: "Apache/2.4.49"}
	client, server := false, false
	for _, s := range WhatSoftwareHTTP("fixture", r) {
		if s.SourceName == "UserAgent" {
			client = true
			if s.Product != "Edge" || s.Vendor != "Microsoft" || s.ObservedHost != r.SrcIP || s.ObservationRole != "client" {
				t.Fatal(s.Software)
			}
		}
		if s.SourceName == "ServerName" {
			server = true
			if s.ObservedHost != r.DstIP || s.ObservationRole != "server" {
				t.Fatal(s.Software)
			}
		}
	}
	if !client || !server {
		t.Fatal("non-vacuous software attribution missing")
	}
}
func TestSoftwareAggregationDoesNotMergeHosts(t *testing.T) {
	old, vi, ei := Store.Items, db.VulnerabilitiesIndex, db.ExploitsIndex
	Store.Items = map[string]*AtomicSoftware{}
	db.VulnerabilitiesIndex = nil
	db.ExploitsIndex = nil
	t.Cleanup(func() { Store.Items = old; db.VulnerabilitiesIndex, db.ExploitsIndex = vi, ei })
	for _, host := range []string{"10.0.0.2", "10.0.0.3"} {
		WriteSoftware([]*AtomicSoftware{{Software: &types.Software{Product: "Edge", Version: "18", ObservedHost: host, ObservationRole: "client"}}}, nil)
	}
	if len(Store.Items) != 2 {
		t.Fatal("host-specific software merged", len(Store.Items))
	}
}
