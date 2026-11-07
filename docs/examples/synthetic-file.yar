rule Netcap_Documentation_Fixture {
    meta:
        description = "Synthetic documentation marker; no malware classification"
    strings:
        $marker = "Netcap synthetic evidence."
    condition:
        $marker
}
