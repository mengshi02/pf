# pf [![Crates.io][crates-badge]][crates-url] [![Build Status][build-badge]][build-url] [![license][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/pf.svg
[crates-url]: https://crates.io/crates/pfio
[build-badge]: https://github.com/mengshi02/pf/actions/workflows/rust.yml/badge.svg
[build-url]: https://github.com/mengshi02/pf/actions
[license-badge]: https://img.shields.io/badge/license-Apache2-orange.svg?style=flat
[license-url]: https://github.com/mengshi02/pf/main/LICENSE

[简体中文](https://github.com/mengshi02/pf/blob/main/README_zh.md)

It is a global regular expression matching print command for network packet filtering, which can be used to capture, search and match network packets and display and humanized output in the form of logs. pf is a command line tool that allows users to analyze network packets by flexibly combining different command parameters.

## Table of Contents 
- [Install](#Install)
- [Usage](#Usage)
- [Examples](#Examples)
    - [how to use](#how-to-use)
    - [packet filter](#packet-filter)
    - [pipeline](#pipeline)
    - [amplifier](#amplifier)
- [Feedback](#Feedback)
- [Maintainers](#Maintainers)

## Install
We have compiled several commonly used executable files for each platform version, you only need to download them locally to use them.

linux | [macOS](https://github.com/mengshi02/pf/raw/main/release/macos/pf) | windows

If you need to compile it yourself, you can do the following:
Note rustc >= 1.6.0

```shell
# cargo build
```

## Usage
If you use it for the first time, you can use `pf -h` to understand the meaning of each parameter. For more usage methods, please refer to [Examples](#Examples).
```shell
# pf -h
pf 0.1.0
A global regular expression print for packet filter

USAGE:
    pf [FLAGS] [OPTIONS] [ARGS]

FLAGS:
    -h, --help           Prints help information
    -i, --ignore-case    Regular expression matching ignore case
    -l, --list-device    List device, view device status
    -m, --multiline      Regular expression matching don't do multiline match (do single-line match instead)
    -p, --promisc        Set promiscuous mode on or off. By default, this is on
    -r, --raw            Record raw packet
    -V, --version        Prints version information
    -v, --verb           Verbose mode (-v, -vv, -vvv, etc.)

OPTIONS:
    -x, --amplify <amplify>      Set the package magnification, by default, the package does not do enlargement
                                 processing, and it only takes effect when this parameter is greater than 1 [default: 1]
    -d, --dev <device>           Opens a capture handle for a device [default: ]
    -M, --matcher <matcher>      Specify a BPF filter, only match the target package [default: ]
    -o, --output <output>        Save matched packets in pcap format to pcap file, if there is no matching rule, the
                                 default is to cap the full package [default: /tmp/0.pcap]
    -s, --snap-len <snap-len>    Set the snaplen size (the maximum length of a packet captured into the buffer). Useful
                                 if you only want certain headers, but not the entire packet [default: 65535]

ARGS:
    <pattern>    Specify a regular expression for matching data [default: ]
    <FILE>...    Files is read packet stream from pcap format files
```

## Examples 
### How to use 
1. To capture network packets, use `-d` to specify the network device, for example: 
```shell
# pf -d en0
```

2. What if you don't know which network device to specify? Use `-l` to view network devices status on your computer, the main available network device pf has marked as `green`. 
```shell
# pf -l
DEVICE        ADDRS                                       MASKS                                                                     BROADCASTS           STATUS                      
en0           fe80::c35:90d7:904c:19f9/172.18.180.63      ffff:ffff:ffff:ffff::/255.255.128.0                                       172.18.255.255       UP | RUNNING                
p2p0                                                                                                                                                     UP | RUNNING                
awdl0         fe80::98da:5eff:fe3d:75eb                   ffff:ffff:ffff:ffff::                                                                          UP | RUNNING                
bridge0                                                                                                                                                  UP | RUNNING                
utun0         fe80::4b47:621f:400e:6c98                   ffff:ffff:ffff:ffff::                                                                          UP | RUNNING                
en1                                                                                                                                                      UP | RUNNING                
en2                                                                                                                                                      UP | RUNNING                
en3                                                                                                                                                      UP | RUNNING                
en4                                                                                                                                                      UP | RUNNING                
lo0           127.0.0.1/::1/fe80::1                       255.0.0.0/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff::                        LOOPBACK | UP | RUNNING     
gif0                                                                                                                                                     (empty)                     
stf0                                                                                                                                                     (empty)                     
XHC0                                                                                                                                                     (empty)                     
XHC1                                                                                                                                                     (empty)                     
ap1                                                                                                                                                      (empty)                     
XHC20                                                                                                                                                    (empty)                     
VHC128                                                                                                                                                   (empty) 
```

3. What does the captured network packet look like after humanized processing? 
```shell
# pf -d en0
waiting for packet from network device ...
================
2022-09-26 14:40:36.577796 +08:00, 2022-09-26 06:40:36.000528893 +08:00, 2-Layer { dest_mac: 84:65:69:BE:90:01 src_mac: A4:83:E7:E3:53:88 type: Ipv4 }, 3-Layer { dest_ip: 10.21.11.47, src_ip: 172.18.180.63, protocol: TCP, header_checksum: 49038, differentiated_services_code_point: 0, explicit_congestion_notification: 0, payload_len: 1472, identification: 0, dont_fragment: true, more_fragments: false, fragments_offset: 0, time_to_live: 64 }, 4-Layer { dest_port: 80, src_port: 59945, sequence_number: 3987034157, acknowledgment_number: 1452843670, data_offset: 5, ns: false, fin: false, syn: false, rst: false, psh: false, ack: true, urg: false, ece: false, cwr: false, window_size: 4096, checksum: 32899, urgent_pointer: 0 }
================
2022-09-26 14:40:36.577830 +08:00, 2022-09-26 06:40:36.000528894 +08:00, 2-Layer { dest_mac: 84:65:69:BE:90:01 src_mac: A4:83:E7:E3:53:88 type: Ipv4 }, 3-Layer { dest_ip: 10.21.11.47, src_ip: 172.18.180.63, protocol: TCP, header_checksum: 49038, differentiated_services_code_point: 0, explicit_congestion_notification: 0, payload_len: 1472, identification: 0, dont_fragment: true, more_fragments: false, fragments_offset: 0, time_to_live: 64 }, 4-Layer { dest_port: 80, src_port: 59945, sequence_number: 3987035609, acknowledgment_number: 1452843670, data_offset: 5, ns: false, fin: false, syn: false, rst: false, psh: false, ack: true, urg: false, ece: false, cwr: false, window_size: 4096, checksum: 18107, urgent_pointer: 0 }
================
2022-09-26 14:40:36.577863 +08:00, 2022-09-26 06:40:36.000528895 +08:00, 2-Layer { dest_mac: 84:65:69:BE:90:01 src_mac: A4:83:E7:E3:53:88 type: Ipv4 }, 3-Layer { dest_ip: 10.21.11.47, src_ip: 172.18.180.63, protocol: TCP, header_checksum: 49038, differentiated_services_code_point: 0, explicit_congestion_notification: 0, payload_len: 1472, identification: 0, dont_fragment: true, more_fragments: false, fragments_offset: 0, time_to_live: 64 }, 4-Layer { dest_port: 80, src_port: 59945, sequence_number: 3987037061, acknowledgment_number: 1452843670, data_offset: 5, ns: false, fin: false, syn: false, rst: false, psh: false, ack: true, urg: false, ece: false, cwr: false, window_size: 4096, checksum: 60563, urgent_pointer: 0 }
```

As shown above, use `pf -d en0` to capture the network packets of the en0 device. Without regular expressions, all network packets are captured by default. For the convenience of display, the collected network is separated by 16 `=` equal signs as separators (if you don't like it, you can add `-s` to turn off this function), and the network packets have also been humanized. Adopt a log structure that approximates json.

4. How to look at the network packets of the log structure? What is the meaning of the fields?
As shown above, the first date is when the log was generated, and the second is when the network packet was collected on the device. `2-Layer` is the data link layer data frame header. `3-Layer` is a network layer data packet. According to the link layer type, it indicates that the network layer is the IPv4 protocol. The network layer also includes protocols such as IPv6 and ICMP, and the content is the network header protocol information. `4-Layer` is the transport layer control information. From the header information of the network layer, it can be found that the protocol is TCP, so the transport layer uses the TCP protocol. There are many transport layer protocols, such as UDP, TLS, DCCP, SCTP, RSVP, PPTP, etc.

6. How to add regular expressions to filter the network packets I need? 
```shell
# pf -d en0 "Ipv4"
# pf -d en0 -i "ipv4" // -i Arguments can ignore regular expression case 
```

6. How to capture raw network packets into a file? 
```shell
# pf -d en0 -r
# pf -d en0 "ipv4" -r -o /tmp/ipv4.pcap
```

7. Load network packets from a file for regular matching. 
```shell
# pf /tmp/ipv4.pcap "TCP"
```

### Packet Filter
This filter is different from the regular expression above. The filter rule here is applied before the original packet is crawled. It can be specified with `-M`. For the filter syntax, please refer to
[BPF syntax](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters)
```shell
# pf -d en0 -M port 80 "TCP" 
```

### Pipeline
The pf command can use the cache to allow multiple matching rules to be combined. You can write it as follows:
```shell
# pf -d en0 -i "ipv4" | pf "TCP"
# pf -d en0 -i "ipv4" | pf "TCP" | pf "127.0.0.1"
```

### Amplifier
You can amplify the matching target network packets, for example, by 10x:
```shell
# pf -d en0 -M dst host 192.168.1.0 -x 10
````

## Feedback

Feel free to dive in! [Open an issue](https://github.com/mengshi02/pf/issues/new) or submit PRs.

Standard Readme follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.


## Maintainers
[@mengshi02](https://github.com/mengshi02)
