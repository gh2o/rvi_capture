# rvi_capture
rvictl for Linux and Windows: capture packets sent/received by iOS devices

A utility to create packet capture dumps from iOS devices; useful for debugging network activity via Wireshark.

Tested on Arch Linux with iOS 14.8.

## Prerequisites

### Linux
`libimobiledevice` and `python3` must be installed. Ensure that the `usbmuxd` daemon is running.

### Windows
`python3` and iTunes must be installed. Ensure that the `AppleMobileDeviceService.exe` process is running.  
`libimobiledevice` will be downloaded as needed.

## Usage

```
./rvi_capture.py [--format {pcap,pcapng}] [--udid UDID] outfile
```
* `--format`: capture format
    * pcap: The default. Can be streamed directly to Wireshark. Packets sent on the cellular interface
      are not Ethernet packets, and will have the source and destination MAC set to 00:00:00:00:00:00.
    * pcapng: Newer, allows for distinguishing between interfaces, but Wireshark does not support 
      treaming captures with this format.
* `--udid`: device UDID  
  The specific device to target. If omitted, the first device found will be used.
* `outfile`: output file or FIFO, or `-` for standard output.

## Using with Wireshark
```
./rvi_capture.py - | wireshark -k -i -
```
Packets sent on the cellular interface can be filtered for via the filter
`eth.src == 00:00:00:00:00:00 && eth.dst == 00:00:00:00:00:00`.
