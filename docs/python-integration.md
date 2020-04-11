---
description: Read Netcap Audit records from Python
---

# Python Integration

## Source Code

The Python library for interacting with netcap audit records has been published here:

{% embed url="https://github.com/dreadl0ck/pynetcap" caption="" %}

## Usage

### Read into python dictionary

Currently it is possible to retrieve the audit records as python dictionary:

```python
#!/usr/bin/python

import pynetcap as nc

reader = nc.NCReader('pcaps/HTTP.ncap.gz')

reader.read(dataframe=False)
print("RECORDS:")
print(reader.records)
```

### Read into pandas dataframe

Retrieving the audit records as pandas dataframe:

```python
#!/usr/bin/python

import pynetcap as nc

reader = nc.NCReader('pcaps/HTTP.ncap.gz')

reader.read(dataframe=True)
print("[INFO] completed reading the audit record file:", reader.filepath)
print("DATAFRAME:")
print(reader.df)
```

