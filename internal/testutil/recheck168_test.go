package testutil

import "testing"

func TestRecheck168FixtureProvenance(t *testing.T) {
	for _, name := range []string{"base_http.pcap", "http_pipelined.pcap", "http_long_header_64k.pcap", "http_nonutf8.pcap", "hv_std_userpass.pcap", "ng_shb_trailer_mismatch.pcapng", "nbns_refresh_fp.pcap", "nbns_query_fp.pcap", "dns_query_fp.pcap", "dns_response_fp.pcap", "v168_udp_uniqflows_10k.pcap"} {
		Recheck168Capture(t, name)
	}
}
