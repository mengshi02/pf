# pf
它是一个对于网络包过滤的全局正则表达式匹配打印命令，它可以用于抓取、搜索和匹配网络包并以日志的方式展示和人性化输出。 pf是一个命令行工具，用户可以通过灵活组合不同的命令参数来分析网络数据包。

## 内容列表
- [安装](#安装)
- [使用说明](#使用说明)
- [示例](#示例)
    - [如何使用](#如何使用) 
    - [包过滤器](#包过滤器)
    - [管道](#管道)
    - [放大器](#放大器)
- [如何反馈](#如何反馈)
- [维护者](#维护者)

## 安装
我们编译好了几个常用的各个平台版本的可执行文件，您只需要下载到本地即可使用。

linux | [macOS](https://github.com/mengshi02/pf/raw/main/release/macos/pf) | windows

如果您需要自行编译，可以进行如下操作：
注意 rustc >= 1.6.0

```shell
# cargo build
```

## 使用说明
如果您第一次使用可以用 `pf -h` 来了解各个参数的意义。更多使用方法，请查阅[示例](#示例)。
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

## 示例
### 如何使用
1. 抓取网络数据包，使用 `-d` 指定网络设备，例如：
```shell
# pf -d en0
```

2. 不知道应该指定哪个网络设备怎么办？使用 `-l` 查看电脑上的网络设备状态，主要的可用网络设备pf已将其标记为`绿色`。
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

3. 抓取到的网络包经过人性化处理后是什么样子？
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

如上所示用 `pf -d en0` 抓取en0设备的网络包，没有加正则表达式默认抓取所有网络包。采集到的网络为了方便展示，每个包用16个`=`等号作为分割符隔离开(如果您不喜欢可以加`-s`可关闭此功能），网络包也已经经过人性化处理，采用一种近似json的日志结构。

4. 日志结构的网络包如何看？字段的含义是什么？
如上所示，第一个日期是日志生成时间，第二个日期是在设备上采集到网络包的时间。`2-Layer`是数据链路层数据帧头。`3-Layer`是网络层数据报文，根据链路层类型指示网络层是IPv4协议，网络层还包括IPv6、ICMP等协议，内容是网络包头协议信息。`4-Layer`是传输层控制信息，从网络层的头部信息中能发现协议是TCP，所以传输层是使用的TCP协议，传输层的协议比较多，像UDP、TLS、DCCP、SCTP、RSVP、PPTP等

6. 如何加正则表达式过滤我需要的网络包？
```shell
# pf -d en0 "Ipv4"
# pf -d en0 -i "ipv4" // -i 参数可以忽略正则表达式大小写
```

6. 如何抓原始网络包到文件中？
```shell
# pf -d en0 -r
# pf -d en0 "ipv4" -r -o /tmp/ipv4.pcap
```

7. 从文件中载入网络包进行正则匹配
```shell
# pf /tmp/ipv4.pcap "TCP"
```

### 包过滤器
这个过滤器与上面的正则表达式不同，这里的过滤器规则应用在原始包抓取之前，可用使用 `-M` 指定，过滤器语法请参阅 [BPF语法](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters)
```shell
# pf -d en0 -M port 80 "TCP" 
```

### 管道
pf命令可以利用缓存使得多个匹配规则能够组合使用，您可以如下这样写:
```shell
# pf -d en0 -i "ipv4" | pf "TCP"
# pf -d en0 -i "ipv4" | pf "TCP" | pf "127.0.0.1"
```

### 放大器
您可以把匹配的目标网络包做放大处理，例如放大10倍:
```shell
# pf -d en0 -M dst host 192.168.1.0 -x 10
```

## 如何反馈

非常欢迎你的加入！[提一个 Issue](https://github.com/mengshi02/pf/issues/new) 或者提交一个 Pull Request。

标准 Readme 遵循 [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) 行为规范。


## 维护者
[@mengshi02](https://github.com/mengshi02)
