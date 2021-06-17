# DEVNOTES

## Add files to git lfs

	git lfs track <file>

## Label selected audit records live

Show output of external analyzer and filter only for records labeled as not normal:

    net capture -read traffic.pcapng -labels ../label/configs/cic-ids2018-attacks.yml -csv -compress=false -include Connection -reassemble-connections=false -conns=false -fileStorage="" -analyzer listen_unix_socket -debug -unix -buf=false -encode | grep -v normal

new analyzer api:

    net capture -read Thursday-01-03-2018.pcapng -reassemble-connections=false -analyzer=connection_dnn -labels ../label/configs/cic-ids2018-attacks.yml -include Connection

