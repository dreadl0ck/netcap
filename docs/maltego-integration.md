# Maltego Integration

## Installation

Ensure netcap is installed and can be found in $PATH:

```
$ net -version
```

{% hint style="info" %}
TODO: /usr/local permissions
{% endhint %}

Next, download install the maltego transformations and enities for netcap:

Netcap offers an OpenFile maltego transform, which will pass filetypes except for executables to the default system application for the corresponding file format. On macOS the open utility will be used for this and on the linux the default is gio open. You can override the application used for this by setting NETCAP\_MALTEGO\_OPEN\_FILE.

