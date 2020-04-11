# Configuration

All default values for flags can be overriden via environment variables, by using the flag name and prefixing it with "NC\_", for example:

```text
$ NC_READ=/home/user/traffic.pcap net capture
```

Additionally, the configuration can be provided as a config file:

TODO: example

An important path for netcap is the one specified by NETCAP\_DATABASE\_SOURCE, as this points to the core location of the libraries for the resolvers package, which is used for the DeviceProfile encoder. The default path is /usr/local/etc/netcap/db if the the env var is unset.

