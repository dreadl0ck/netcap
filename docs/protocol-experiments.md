# Active protocol experiments

`net investigate` includes bounded experiment tools alongside passive evidence
queries. Commands that listen or contact endpoints belong in a controlled lab
or an explicitly authorized engagement. They are not required for offline PCAP
analysis.

| Command | Purpose |
| --- | --- |
| `exchange` | One bounded TCP/UDP exchange from a versioned JSON specification |
| `protocol-fields` | Test a framing/field hypothesis on contiguous directional bytes |
| `tls-capture` | External `tshark` TLS analysis using supplied session secrets |
| `protocol-proxy` | One framed TCP session, optional TLS termination and bounded edits |
| `protocol-server` | Bounded server emulation |
| `protocol-access` | Role/state/resource matrix with reset controls |
| `protocol-generate`, `protocol-corpus` | Deterministic grammar/field/state/byte cases |
| `protocol-fuzz`, `protocol-reproduce` | Controlled campaigns, minimization and reproduction |
| `protocol-boundary` | Separate target rejection from harness limits/timeouts |
| `protocol-triage` | Import hashed process/debugger evidence; impact remains unverified |

## Offline hypotheses first

Create the [lab fixtures](investigation-walkthrough.md#create-the-evidence),
then use the complete version-1 grammar in
[`docs/examples/grammar.json`](examples/grammar.json). Its fixed seven-byte
frame contains version `1`, length `5` and five UTF-8 bytes. `expected` byte
assertions use JSON base64 (`AQ==` is one byte with value 1).

<!-- docs:run grammar -->
```sh
net investigate protocol-fields -spec docs/examples/grammar.json \
  -read doc-fixtures/client.bin -compare doc-fixtures/other-client.bin \
  > doc-fixtures/grammar-comparison.json
```

Expect one frame in each input and a `text` difference from `hello` to `world`.
The `size` field is interpreted, not automatically validated against the body;
use explicit length/framing constraints when that relationship is part of the
hypothesis. Ordinal comparison does not repair insertion/deletion alignment.

Use the versioned grammar types and examples in
[`internal/protocoltest`](https://github.com/dreadl0ck/netcap/tree/v0.15.2/internal/protocoltest).
`client.bin` must be contiguous evidence; capture gaps cannot be repaired by
concatenation. Frame insertion can shift ordinal alignment. A successful parse
shows that bytes fit a hypothesis, not that its application semantics are true.

## Supplied TLS secrets

```sh
net investigate tls-capture -read tls.pcapng -key-log secrets.log -stream 0
```

Install compatible `tshark` separately. Provide the correct capture/stream and
NSS-format session-secret log; Netcap does not derive TLS secrets from passive
traffic. Output binds input, key-log and plaintext hashes to tool version. Secret
material is not copied into the report. Endpoint order follows the dissector's
output, not a guessed client role.

## Active controls

`exchange -spec exchange.json` and related commands have time, frame, byte and
input-size bounds. Byte fields use JSON base64. Configure certificate roots and
paired client certificate/key explicitly for mTLS; TLS verification is not
disabled merely to make an experiment succeed.

Keep a valid baseline/control case, exact input/output bytes, process context and
reproduction steps. A matching marker is not general exploitation proof. A
timeout/budget-stop is not target rejection; a debugger artifact is not verified
impact. [Packet evidence](evidence.md) preserves passive source context separately.
