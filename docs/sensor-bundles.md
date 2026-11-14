# Signed sensor bundles

Use sensor bundles to move finished capture output from one network to another, for example from a sensor on an air-gapped plant network to an analysis workstation. The sensor seals its audit output into a signed bundle. You carry it over on removable media or another file transfer, and the receiving side verifies and imports it.

The commands are `net investigate sensor-seal`, `sensor-import` and `sensor-prune`. They are independent of the live agent/collector connection ([Distributed collection](distributed-collection.md)) and of the Ed25519 community database publisher. Bundles are authenticated with HMAC-SHA256 and a shared key.

## Create a key

Create one random key per sensor and give a copy to the receiving side over a channel you trust. Keys are 32 to 4096 bytes read from a file.

```sh
openssl rand -out sensor.key 32
chmod 600 sensor.key
```

## Seal output on the sensor

Seal the audit directory a capture wrote:

```sh
net investigate sensor-seal -read /var/netcap/audit -out /var/netcap/sealed \
  -sensor-id plant-a -key-file /etc/netcap/sensor.key -retention 24h \
  > sealed.json
```

The command prints a JSON string with the path of the new bundle directory, `/var/netcap/sealed/plant-a/<run-id>/`. The directory contains `sensor-bundle.json`. The seal store is created with mode 0700. If an existing store is readable by group or others, the command stops instead of changing its permissions.

Print the bundle path and copy that directory to your transfer media:

```sh
jq -r . sealed.json
```

## Verify and import on the receiving side

```sh
net investigate sensor-import -read /media/usb/plant-a/<run-id> \
  -out /srv/netcap/imported -sensor-id plant-a -key-file /etc/netcap/plant-a.key \
  -retention 24h > imported.json
```

The receiver sets the sensor ID, key, size limit and retention itself. A bundle cannot grant itself a namespace. Import checks the manifest signature, the expiry and every file hash. It cannot confirm who the endpoints or users named in the packets are.

| Option       | Default / requirement                                                   |
| ------------ | ----------------------------------------------------------------------- |
| Key material | 32–4096 bytes read from a file                                          |
| `-max-bytes` | 1 GiB of imported bundle data                                           |
| `-retention` | 24h by default, at most 30 days                                         |
| `-timeout`   | 2 minutes                                                               |
| Sensor ID    | Lowercase ASCII letters and digits with `_` or `-`, up to 64 characters |

HMAC means anyone who holds the key can create a valid bundle. If you need proof of which party signed, bundles do not provide it.

## Prune expired imports

`sensor-prune` deletes expired imports in the namespace you name:

```sh
net investigate sensor-prune -out /srv/netcap/imported -sensor-id plant-a \
  -key-file /etc/netcap/plant-a.key -retention 24h > pruned.json
```

Run it from cron or a systemd timer on the receiving side. It does not touch the original captures or the sensor's seal store. Those have their own retention.
