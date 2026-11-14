# Active protocol experiments

`net investigate` includes experiment commands next to the passive evidence queries. Commands that listen or contact endpoints belong in a lab or an authorized engagement. Offline PCAP analysis does not need them.

| Command                                | Purpose                                                             |
| -------------------------------------- | ------------------------------------------------------------------- |
| `exchange`                             | One TCP/UDP exchange from a versioned JSON specification            |
| `protocol-fields`                      | Test a framing or field hypothesis on contiguous one-way bytes      |
| `tls-capture`                          | TLS analysis with external `tshark`, using supplied session secrets |
| `protocol-proxy`                       | One framed TCP session, optional TLS termination and limited edits  |
| `protocol-server`                      | Server emulation with limits                                        |
| `protocol-access`                      | Role/state/resource matrix with reset controls                      |
| `protocol-generate`, `protocol-corpus` | Deterministic grammar, field, state and byte cases                  |
| `protocol-fuzz`, `protocol-reproduce`  | Fuzzing campaigns, minimization and reproduction                    |
| `protocol-boundary`                    | Tell target rejection apart from harness limits and timeouts        |
| `protocol-triage`                      | Import hashed process/debugger evidence; impact stays unverified    |

## Offline hypotheses first

Say you captured traffic to a device with a proprietary TCP protocol and suspect that each message is a version byte, a length byte and some text. Save one direction of two sessions as raw bytes, named `client-a.bin` and `client-b.bin`. In Wireshark, use Follow TCP Stream, show one direction and save as Raw. The bytes must be contiguous, because a capture gap cannot be repaired by joining files.

Then describe the frame in a grammar and compare the two files. `docs/examples/grammar.json` in the [Netcap repository](examples/grammar.json) is a complete version-1 grammar for a seven-byte frame: version `1`, length `5` and five UTF-8 bytes. `expected` byte assertions use JSON base64 (`AQ==` is one byte with value 1).

```sh
net investigate protocol-fields -spec docs/examples/grammar.json \
  -read client-a.bin -compare client-b.bin \
  > grammar-comparison.json
```

If `client-a.bin` holds one frame with the text `hello` and `client-b.bin` one frame with the text `world`, you get one frame in each input and a `text` difference from `hello` to `world`. Write a grammar for your own protocol to match your own streams.

The `size` field is read but not checked against the body. If that relationship matters, add length or framing constraints. Comparison is by position, so an inserted or deleted frame shifts everything after it. The grammar types and examples are in the [protocoltest sources](https://github.com/dreadl0ck/netcap/tree/v0.15.2/internal/protocoltest). A successful parse shows that the bytes fit your hypothesis, not that your reading of the protocol is right.

## Supplied TLS secrets

```sh
net investigate tls-capture -read tls.pcapng -key-log secrets.log -stream 0
```

Install a compatible `tshark` separately. Give the right capture and stream number, and a session-secret log in NSS format. Netcap cannot derive TLS secrets from passive traffic. The output ties the input, key-log and plaintext hashes to the tool version, and secret material is not copied into the report. Endpoint order follows the dissector's output, not a guessed client role.

## Active controls

`exchange -spec exchange.json` and the related commands limit time, frames, bytes and input size. Byte fields use JSON base64. For mTLS, configure the certificate roots and a matching client certificate and key. TLS verification is never turned off to make an experiment pass.

Keep a valid baseline case, the exact input and output bytes, the process context and the steps to reproduce. A matching marker is a lead; confirm exploitation separately. A timeout or budget stop says nothing about whether the target rejected the input, and a debugger artifact leaves impact unverified. [Packet evidence](evidence.md) keeps the passive source context separately.
