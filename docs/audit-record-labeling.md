# Labeling datasets

`net label` adds labels to existing audit records and writes labeled CSV files. Use it to build training data for machine learning, for example an intrusion detection model trained on traffic that Suricata rules have flagged. Labels come from Suricata alerts or from a custom mapping you provide.

A label is whatever the rules said about the traffic. It is not verified ground truth.

## Label a capture with Suricata

Install Suricata and configure its rules first. Labeling writes dataset files into `-out`, so work on a copy of your audit output.

```sh
net capture -read traffic.pcap -out labeling-audit -dpi=false
net label -read traffic.pcap -out labeling-audit \
  -suricata-config /usr/local/etc/suricata/suricata.yaml
```

`-read` is the PCAP that Suricata scans. `-out` is the existing audit directory from the first command. Use the path of your own Suricata config. The default is `/usr/local/etc/suricata/suricata.yaml`.

Keep a record of the PCAP hash, the Netcap and Suricata versions, and the ruleset revision next to the dataset so you can reproduce it.

| Flag              | Meaning                                                 |
| ----------------- | ------------------------------------------------------- |
| `-description`    | Use the alert description instead of the classification |
| `-strict`         | Fail on duplicate alert timestamps                      |
| `-collect`        | Append classifications for duplicate timestamps         |
| `-exclude`        | Exclude selected Suricata classifications               |
| `-disable-layers` | Do not map layer types by timestamp                     |
| `-sep`            | CSV separator, a comma by default                       |
| `-custom`         | Load a custom mapping instead of running Suricata       |

## Custom mappings

With `-custom`, the output files are named `TYPE_labeled.csv.gz` and have a `result` column. Records that match no mapping entry get the label `normal`. That means no label matched. It does not mean the traffic is benign.

The mapping file must use the format `net label` reads. Try it on a small capture before you label a large one.

## Check the labels before you train

Several things change label quality: alerts with the same timestamp, packets dropped during capture, and traffic your ruleset does not cover. Spot-check a sample against the PCAP.

Split training and test data by capture, or by host and time range. If the same conversation lands in both sets, your test results will look better than they are.
