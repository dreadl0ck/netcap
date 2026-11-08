# Credential observations

`Secret` records retain supported credential/authentication observations from
visible traffic. A captured password, challenge/response or token is sensitive
evidence; the record's existence does not establish successful authentication.

```sh
net capture -read traffic.pcap -out credential-audit -dpi=false
net dump -read credential-audit/Secret.ncap.gz -fields
net dump -read credential-audit/Secret.ncap.gz -json
```

Only inspect a file the capture produced. No `Secret` records can mean absent
plaintext, encryption, unsupported framing, disabled harvesters or insufficient
captured bytes. It does not establish that authentication never occurred.

## Review each observation

Current `WriteSecret` retains every emitted occurrence, including repeated
credentials in the same flow and hash-only observations. Count occurrences and
distinct credential identities separately; repetition can represent different
transactions (`internal/decoder/stream/secret/secret.go`, `types/secret.go`).

| Evidence | Interpretation |
| --- | --- |
| Protocol and endpoints | Identify the owning framed exchange and initiator; raw token-shaped bytes alone do not establish host attribution |
| Credential representation | Distinguish plaintext, encoded text, challenge/response and hashed material; base64 is encoding, not encryption |
| `Notes` / protocol response | Preserve observed success, rejection or unknown result; TCP reset/timeout alone is not an authentication failure |
| Capture time and stream scope | Join only to the relevant connection and visible exchange |
| User/account names | Advertised or observed identities; not proof of the human operator |
| `AuthSuccessSet` / `AuthSuccess` | Only a set outcome distinguishes observed success from rejection; unset remains unknown |
| `Realm`, `Uri`, `SipCallId` | Preserve the protocol's observed context; absent fields cannot be inferred from another occurrence |
| `CommunityID` | Tuple correlation only; qualify capture/source scope, time and session reuse before a cross-record join |

SMTP LOGIN/PLAIN results and STARTTLS boundaries are described in
[email extraction](mail-extraction.md). Windows account/principal evidence and
directory subjects are covered by [hosts and identity](host-identity.md).
Encrypted sessions can expose endpoints/timing while hiding the result.

## Configure and qualify harvesters

The [transfer lab](investigation-walkthrough.md) contains a synthetic HTTP Basic
header encoding `lab-user:lab-password`. These are fictional values embedded
offline, never submitted to a server. Inspect `doc-fixtures/audit/Secret.ncap.gz`
and the owning HTTP record; the DNS-only benign control must have no credential
observation. The HTTP 200 response alone does not prove which authentication
policy a real service applied.

`capture -harvesters-config` loads the feature-specific YAML described by the
checkout's `configs/` and harvester implementation. Use the installed help for
per-stream byte bounds and selection; `-payload` is not a universal credential
enable/disable control. Generic regex harvesting and protocol-specific parsing
have different false-positive boundaries.

Test configuration on a synthetic positive exchange and a benign conversation
that contains similar text outside an authentication frame. Do not replay real
credentials to validate extraction. The WebUI's Credentials view and MCP
`list_secrets`/`list_auth_activity` are distinct views; check the
[tool reference](mcp/tools.md) before automation.

## Preserve and share

[Scoped rule joins](RULES_ENGINE.md#scoped-capture-time-rules) retain hash-only
contributors and bounded matched-record projections. Secret alert projections
and Prometheus labels exclude credential material; [webhook notices](RULES_ENGINE.md#durable-webhook-delivery)
also omit raw records, notes and credential fields. This protection applies to
those projections, not the original `Secret.ncap.gz`, raw `dump -json` output or
the local Credentials view. Some specialist views filter records without a
username/password; use the audit file to check hash-only occurrences.

Limit access to the original capture, `Secret` files and screenshots. Redacting
an exported table does not redact retained payloads or other output files.
Preserve source references for authorized incident handling; avoid including
credential values in rule names, public issues or documentation examples.
