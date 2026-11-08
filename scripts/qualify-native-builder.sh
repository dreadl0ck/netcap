#!/bin/sh
# Run inside an isolated builder container on the target CPU.
set -eu
pkg-config --exact-version=1.22.0 yara_x_capi
go version
uname -m
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/probe.c" <<'C'
#include <assert.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <yara_x.h>

static void matched(const struct YRX_RULE *rule, void *count) {
    (void)rule;
    ++*(int *)count;
}

int main(void) {
    struct YRX_COMPILER *compiler = NULL;
    struct YRX_SCANNER *scanner = NULL;
    int count = 0;
    assert(yrx_compiler_create(0, &compiler) == YRX_SUCCESS);
    assert(yrx_compiler_add_source(compiler, "rule candidate { strings: $a = \"netcap-native-positive\" condition: $a }") == YRX_SUCCESS);
    struct YRX_RULES *rules = yrx_compiler_build(compiler);
    assert(rules && yrx_rules_count(rules) == 1);
    assert(yrx_scanner_create(rules, &scanner) == YRX_SUCCESS);
    assert(yrx_scanner_on_matching_rule(scanner, matched, &count) == YRX_SUCCESS);
    const uint8_t positive[] = "netcap-native-positive";
    const uint8_t negative[] = "negative-control";
    assert(yrx_scanner_scan(scanner, positive, sizeof(positive)) == YRX_SUCCESS);
    assert(count == 1);
    count = 0;
    assert(yrx_scanner_scan(scanner, negative, sizeof(negative)) == YRX_SUCCESS);
    assert(count == 0);
    yrx_scanner_destroy(scanner);
    yrx_rules_destroy(rules);
    yrx_compiler_destroy(compiler);
    assert(yrx_compiler_create(0, &compiler) == YRX_SUCCESS);
    assert(yrx_compiler_add_source(compiler, "rule invalid {") != YRX_SUCCESS);
    yrx_compiler_destroy(compiler);

    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    assert(handle);
    struct bpf_program filter;
    assert(pcap_compile(handle, &filter, "udp and dst port 53", 1, PCAP_NETMASK_UNKNOWN) == 0);
    const unsigned char packet[] = {
        0,0,0,0,0,0, 0,0,0,0,0,0, 8,0,
        0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,192,0,2,2,
        0x04,0xd2,0,53,0,8,0,0
    };
    struct pcap_pkthdr header = { .caplen = sizeof(packet), .len = sizeof(packet) };
    assert(pcap_offline_filter(&filter, &header, packet) != 0);
    pcap_freecode(&filter);
    assert(pcap_compile(handle, &filter, "tcp", 1, PCAP_NETMASK_UNKNOWN) == 0);
    assert(pcap_offline_filter(&filter, &header, packet) == 0);
    pcap_freecode(&filter);
    pcap_close(handle);
    puts(pcap_lib_version());
    puts("PASS: YARA compile/match/nonmatch/invalid-source; BPF match/nonmatch");
    return 0;
}
C
cc -o "$work/probe" "$work/probe.c" $(pkg-config --cflags --libs yara_x_capi libpcap) -Wl,-rpath,/usr/local/lib
"$work/probe"
