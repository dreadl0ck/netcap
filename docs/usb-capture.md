# USB Capture

USB live capture is now possible, currently the following Audit Records exist: USB and USBRequestBlockSetup.

To capture USB traffic live on macOS, install wireshark and bring up the USB interface:

```text
$ sudo ifconfig XHC20 up
```

Now attach netcap and set baselayer to USB:

```text
$ net.cap -iface XHC20 -base usb
```

To read offline USB traffic from a PCAP file use:

```text
$ net.cap -r usb.pcap -base usb
```

Don't forget to set the **-payload** flag if you want to preserve the data being transmitted!

