# CSV, JSON and record inspection

`net dump` reads audit files. Use it to look at records and to convert them to CSV or JSON. (`net export` is a different command that feeds Prometheus.)

## Look at a record file

```sh
net dump -read analysis/UDP.ncap.gz -header
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -json
```

`-header` prints the file header, and `-fields` lists the field names, one per line. JSON output is one object per line, not a single array. Without `-csv` or `-json`, `dump` prints a structured view for the terminal.

## Export columns to CSV

Pull the timestamp and ports out of a DNS capture:

```sh
net dump -read analysis/UDP.ncap.gz -csv -sep ',' \
  -select Timestamp,SrcPort,DstPort > udp.csv
```

The default CSV separator is `;`, so pass `-sep ','` if your tool expects commas. `-select` chooses and orders the columns but does not switch on CSV, so keep `-csv`. Nested records, maps and repeated values do not flatten cleanly, so look at them with `-json` first. Spreadsheet programs can run cell contents as formulas, so don't open CSV from untrusted traffic without checking it.

## Filter records

```sh
net dump -read analysis/UDP.ncap.gz -filter 'DstPort == 53' -json
```

The expression is checked against the record type of the file. Keep the shell quoting around it, and check for errors, because a failing expression is not the same as zero matches. TCP and UDP ports are numbers. Connection ports are strings and need quotes. See [Filtering](FILTERING.md).

## Time order

`dump` can sort records by capture time with `-sort-time`. Check `dump -h` for the options. Sorting uses temporary files, so memory use stays low. Without it, records can come out of capture order, because streams finish at different times and several writers run at once. Sorting changes only the order of the output, not the records. `dump` can show timestamps in UTC, while the stored value is always Unix nanoseconds.

Shell `>` overwrites an existing file, so write exports to a new name if you want to keep the previous one. To save packets together with a record of what was selected, use [`investigate packet-evidence`](evidence.md#export-packet-evidence).
