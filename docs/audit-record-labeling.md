# Audit Record Labeling

`net label` joins Suricata alerts or custom mappings to existing audit records
and produces labeled CSV datasets. A generated label is a mapping result, not
independent ground truth about compromise.

## Suricata workflow

Install Suricata and configure its rules before running this example. Keep a
working copy of the audit output: labeling writes dataset files into `-out`.

```sh
net capture -read traffic.pcap -out labeling-audit -dpi=false
net label -read traffic.pcap -out labeling-audit \
  -suricata-config /usr/local/etc/suricata/suricata.yaml
```

The configuration path is an example; use the installed Suricata configuration.
`-read` is the PCAP scanned by Suricata; `-out` also identifies the existing audit
directory. Preserve the PCAP hash, Netcap/Suricata versions and ruleset revision
beside the dataset.

| Flag | Meaning |
| --- | --- |
| `-description` | Use alert description rather than classification |
| `-strict` | Fail on duplicate alert timestamps |
| `-collect` | Append classifications for duplicate timestamps |
| `-exclude` | Exclude selected Suricata classifications |
| `-disable-layers` | Disable layer mapping by timestamp |
| `-sep` | CSV separator, default comma for this command |
| `-custom` | Load a custom mapping instead of running the Suricata path |

## Dataset interpretation

Custom mapping output uses `TYPE_labeled.csv.gz` and a `result` column. An
unmatched custom mapping becomes `normal` in `internal/label/custom.go`; that
spelling means no matching label, not proof of benign traffic. Timestamp
collisions, capture loss and rule coverage can change label quality.

Inspect `internal/label/manager` before defining custom mappings; do not assume
an arbitrary two-column CSV is accepted. Verify a small known fixture before
labeling a large corpus. Split train/test sets by capture or host/time context
where appropriate to avoid leaking duplicate conversations across both sets.
