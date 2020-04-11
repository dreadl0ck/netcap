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

Netcap offers an OpenFile maltego transform, which will pass filetypes except for executables to the default system application for the corresponding file format. On macOS the open utility will be used for this and on the linux the default is gio open. You can override the application used for this by setting NC\_MALTEGO\_OPEN\_FILE.

Currently there are 20 Entities and 42 Transformations implemented.

{% file src=".gitbook/assets/netcap-maltego-config-v0.5.mtz.zip" caption="NETCAP Maltego Transformations and Entities" %}

