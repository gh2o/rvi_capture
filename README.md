# rvi_capture
rvictl for Linux, macOS, and Windows: capture packets sent/received by iOS devices

A utility to create packet capture dumps from iOS devices; useful for debugging network activity via Wireshark.

Tested on Arch Linux with iOS 14.8 and macOS 13.1 with iOS 17.4.

## Prerequisites

### Linux and macOS
`libimobiledevice` and `python3` must be installed. Ensure that the `usbmuxd` daemon is running.

### Windows
`python3` and iTunes must be installed. Ensure that the `AppleMobileDeviceService.exe` process is running.  
`libimobiledevice` will be downloaded as needed.

## Usage

```
./rvi_capture.py [--format {pcap,pcapng}] [--udid UDID] outfile
```
* `--format`: capture format
    * pcapng: The default. Newer and allows for distinguishing between interfaces.
      Wireshark 3.0+ supports streaming captures with this format.
    * pcap: Older format for compatibility.
* `--udid`: device UDID  
  The specific device to target. If omitted, the first device found will be used.
* `outfile`: output file or FIFO, or `-` for standard output.

## Using with Wireshark
```
./rvi_capture.py - | wireshark -k -i -
```

### Tips
- In Wireshark, you can filter for a particular network interface based on the
  `frame.interface_name` field. Here are some possible values (as tested on iOS 14.8):
  - `en0`: wifi interface
  - `pdp_ip0`: cellular interface
  - `ipsec1`: IPSec outer transport for VoLTE
  - `ipsec3`: IPSec inner transport for VoLTE
