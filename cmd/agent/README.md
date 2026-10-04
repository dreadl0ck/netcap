# NET.AGENT

*net agent* captures live traffic and streams the audit records to a *net collect* collection server over mutually authenticated TLS 1.3.

Setup, protocol and limits: [docs/distributed-collection.md](../../docs/distributed-collection.md).

## Usage

    $ net agent -gen-keypair
    wrote agent.crt and agent.key
    agent fingerprint (add to the collector's -clients file):
    b69d2c0a... <name>

    $ net agent -server-fingerprint 189b7718... -addr collector:1335 -iface eth0

The collector prints its fingerprint on `net collect -gen-keypair` and at startup. List every flag with `net agent -h`.
