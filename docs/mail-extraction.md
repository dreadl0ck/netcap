# Email extraction

Netcap decodes plaintext POP3, IMAP and SMTP. It writes transaction records, message bodies and attachments, and authentication observations as separate outputs.

Analyse a capture of a mail client talking to a server, then look at the records:

```sh
net capture -read mail.pcap -out mail-audit -dpi=false
net dump -read mail-audit/SMTP.ncap.gz -fields
net dump -read mail-audit/Secret.ncap.gz -json
```

Check which files the capture wrote first. You only get a file for the protocols that appear in the traffic.

## POP3

A fetched message produces `Mail` and `MailPart` records with the headers and bodies. A conversation that contains only the server banner has no message. After a successful `STLS`, the rest of the session is encrypted and Netcap stops parsing it.

## IMAP

Plaintext IMAP sessions produce protocol records. Literals split across segments, partial responses and missing bytes can leave a message incomplete. After a successful `STARTTLS`, Netcap stops parsing the session.

## SMTP

SMTP produces command and response records, and records `AUTH LOGIN` and `AUTH PLAIN` logins as `Secret` records. `Secret.Notes` says whether the login succeeded, was rejected, or ended with an unknown result. A dropped connection or an incomplete response is recorded as unknown, not as a failed login. After a successful `STARTTLS`, Netcap stops parsing the session.

## Reading the results

Check the field names in `types/netcap.proto` or with `dump -fields`. Mail headers such as `From` are supplied by the sender and can be forged. Treat captured credentials, recipients and attachments with the same care as the capture itself. To follow an attachment, see [file extraction](file-extraction.md) and [evidence linking](evidence.md).
