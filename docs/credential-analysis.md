# Credential observations

`Secret` records hold the credentials and authentication data netcap finds in traffic: passwords, challenge/response pairs and tokens. Treat them as sensitive. A record shows that a credential was sent, not that the login succeeded.

To look for cleartext logins, run a capture that contains one (for example a plain HTTP or FTP login) and dump the `Secret` file:

```sh
net capture -read login-capture.pcap -out credential-audit -dpi=false
net dump -read credential-audit/Secret.ncap.gz -fields
net dump -read credential-audit/Secret.ncap.gz -json
```

If you get no `Secret` records, the traffic may be encrypted, use an unsupported protocol or framing, the harvesters may be disabled, or the capture may not hold enough bytes.

## Review each observation

Every occurrence is kept, including repeated credentials in one flow and hash-only observations. Count occurrences and distinct credentials separately, because repeats can be separate logins.

| Field                            | What it tells you                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------------ |
| Protocol and endpoints           | The exchange the credential came from and who started it                                   |
| Credential representation        | Plaintext, encoded text, challenge/response or hash. Base64 is encoding, not encryption    |
| `Notes` / protocol response      | Whether the server accepted or rejected it. A TCP reset or timeout is not a failed login   |
| Capture time and stream          | Use these to join to the right connection                                                  |
| User/account names               | The name sent in the exchange, which is not necessarily the person behind it               |
| `AuthSuccessSet` / `AuthSuccess` | The outcome is known only when `AuthSuccessSet` is true. Otherwise it is unknown           |
| `Realm`, `Uri`, `SipCallId`      | Protocol context from this occurrence only. Don't fill gaps from another record            |
| `CommunityID`                    | Identifies the connection tuple. Tuples get reused, so check the time range before joining |

SMTP LOGIN/PLAIN results and STARTTLS boundaries are in [email extraction](mail-extraction.md). Windows accounts and directory subjects are in [hosts and identity](host-identity.md). Encrypted sessions show endpoints and timing but hide the result.

## Configure and qualify harvesters

HTTP Basic authentication is a good first test. The `Authorization: Basic` header is the base64 of `user:password`, so one login to a test web app over plain HTTP gives you a record to inspect. Compare it with the HTTP record for the same request.

`capture -harvesters-config` loads a YAML file that configures the harvesters. See the `configs/` directory of the netcap repository for the format. `-hbsize` sets how many bytes of each stream go to the harvesters (default 256, recommended 512 to 8192), and `-reCustom` adds your own regex.

Test a configuration on a capture of a real login to a system you control, and on a capture of ordinary browsing. Generic regex harvesting can match text outside an authentication exchange, so check each match against the owning protocol exchange. Don't replay real credentials to test extraction.

The WebUI's Credentials view and the MCP tools `list_secrets` and `list_auth_activity` show different slices of the data. Check the [tool reference](mcp/tools.md) before you automate.

## Preserve and share

[Scoped rule joins](RULES_ENGINE.md#scoped-capture-time-rules) keep hash-only references to the records they join. Secret alert projections, Prometheus labels and [webhook notices](RULES_ENGINE.md#durable-webhook-delivery) leave out credential material.

The original `Secret.ncap.gz`, raw `dump -json` output and the local Credentials view still contain it. Some specialist views skip records without a username or password, so use the audit file to find hash-only occurrences.

Limit access to the capture, the `Secret` files and screenshots. Redacting an exported table doesn't redact retained payloads or other output files. Keep source references for incident handling, and keep credential values out of rule names, public issues and documentation.
