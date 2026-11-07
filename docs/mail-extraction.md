# Email Extraction

Go Netcap decodes supported plaintext POP3, IMAP and SMTP exchanges. Transaction
records, message bodies/attachments and authentication observations are separate
outputs; visibility depends on captured bytes and protocol state.

```sh
net capture -read mail.pcap -out mail-audit -dpi=false
```

Inspect files actually emitted, for example:

```sh
net dump -read mail-audit/SMTP.ncap.gz -fields
net dump -read mail-audit/Secret.ncap.gz -json
```

## POP3

Supported retrievals can contain parsed `Mail`/`MailPart` metadata and bodies.
A banner-only conversation does not imply a fetched message. Successful STLS
ends plaintext parsing; subsequent encrypted bytes are not mail text.

## IMAP

Supported plaintext exchanges expose protocol records. Literal framing,
partial responses and missing bytes can limit reconstruction. Successful
STARTTLS ends plaintext parsing; the old statement that all IMAP support is
future work is obsolete.

## SMTP

SMTP command/response records and LOGIN/PLAIN authentication observations are
available. `Secret.Notes` distinguishes observed success, rejection and unknown
result. A failed connection or incomplete response is not an authentication
failure. Successful STARTTLS ends plaintext parsing.

## Interpretation

Use current record fields from `types/netcap.proto`; historical schema snippets
with string timestamps are obsolete. Mail headers are sender-supplied evidence,
not verified ownership. Credentials, recipients and attachments require the same
access boundaries as the original capture. Follow [file extraction](file-extraction.md)
and [evidence linking](evidence.md) to trace reconstructed content.
