# Filter Expression Examples

This directory contains example filter expressions for common use cases with NETCAP.

## Usage

Filters can be applied using the `net dump` command:

```bash
net dump -read <audit_record_file>.ncap.gz -filter "<expression>"
```

You can also load filter expressions from files:

```bash
net dump -read TCP.ncap.gz -filter "$(cat http_specific_host.txt)"
```

## Available Examples

- **basic_filters.txt** - Simple single-condition filters
- **network_filters.txt** - Network-based filtering (IPs, subnets, ports)
- **protocol_filters.txt** - Protocol-specific filters (HTTP, DNS, TLS)
- **security_filters.txt** - Security-focused detection filters
- **performance_filters.txt** - Filters for performance analysis
- **complex_filters.txt** - Advanced multi-condition filters

## See Also

- [FILTERING.md](../../FILTERING.md) - Complete filtering documentation
- [RULES_ENGINE.md](../../RULES_ENGINE.md) - Rules engine documentation

