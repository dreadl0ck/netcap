# NET.COLLECT

*net collect* receives audit records from *net agent* sensors and writes them to `<out>/<client name>/<Type>.ncap.gz`. Only agents whose key is in the `-clients` allowlist can connect, and the directory name comes from that allowlist.

Setup, protocol and limits: [docs/distributed-collection.md](../../docs/distributed-collection.md).

## Usage

    $ net collect -gen-keypair
    wrote collector.crt and collector.key
    server fingerprint (pass to agents as -server-fingerprint):
    189b7718...

    $ echo "b69d2c0a... sensor-dmz" > clients.txt
    $ net collect -clients clients.txt -addr 0.0.0.0:1335 -out collected

SIGINT or SIGTERM waits for in-flight batches, then finalizes every file. List every flag with `net collect -h`.
