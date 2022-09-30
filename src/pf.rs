// Copyright 2022 pf Project Authors. Licensed under Apache-2.0.

use std::borrow::Borrow;
use std::path::PathBuf;
use structopt::StructOpt;
use std::convert::From;
use std::fmt::Debug;
use std::io;
use std::io::BufRead;
use std::process::exit;
use pcap::{Capture, Active, Device, Savefile, State, Address, DeviceFlags, IfFlags};
use pcre2::bytes::{Match, Regex, RegexBuilder};
use pcap::Packet;
use etherparse::{InternetSlice, ReadError, SlicedPacket, Ipv4HeaderSlice, EtherType, VlanHeader, TransportSlice, Ipv4Header, Ipv6Header, Icmpv4Type, Icmpv6Header, Icmpv4Header, TcpHeader, UdpHeader, Ethernet2Header};
use macaddr::MacAddr6;
use tokio::sync::broadcast;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::broadcast::{Sender, Receiver};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice::Split;
use chrono::prelude::*;
use tokio::sync::broadcast::error::{RecvError, SendError};
use colored::*;

pub const CHANNEL_CAPACITY: usize = 4096;
pub const MAX_LAGGED: usize = (CHANNEL_CAPACITY as f32 * 1.5 / 2 as f32) as usize;
pub const SPLITTER: &str = "================";
pub const DATA_LINK_LAYER: &str = "2-Layer";
pub const NETWORK_LAYER: &str = "3-Layer";
pub const TRANSPORT_LAYER: &str = "4-Layer";
pub const APP_LAYER: &str = "5-Layer";

#[derive(Debug)]
pub enum Error {
    NotFound,
    UnexpectedError
}

impl From<io::Error> for Error {
    fn from(_e: io::Error) -> Error {
        Error::UnexpectedError
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Status {
    Online,
    Offline,
    Pipeline
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    ICMP = 0x01,
    IGMP = 0x02,
    TCP  = 0x06,
    UDP  = 0x11,
}

impl Protocol {
    pub fn from(value: u8) -> Option<Protocol> {
        use self::Protocol::*;
        match value {
            0x01 => Some(ICMP),
            0x02 => Some(IGMP),
            0x06 => Some(TCP),
            0x11 => Some(UDP),
            _ => None
        }
    }
}

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "pf", about = "A global regular expression print for packet filter")]
pub struct Opt {
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verb", parse(from_occurrences))]
    verbose: u8,

    /// Set promiscuous mode on or off. By default, this is on.
    #[structopt(short = "p", long)]
    promisc: bool,

    /// Regular expression matching ignore case.
    #[structopt(short = "i", long)]
    ignore_case: bool,

    /// Regular expression matching don't do multiline match (do single-line match instead)
    #[structopt(short = "m", long)]
    multiline: bool,

    /// Specify a regular expression for matching data.
    #[structopt(default_value = "")]
    pattern: String,

    /// Set the snaplen size (the maximum length of a packet captured into the buffer).
    /// Useful if you only want certain headers, but not the entire packet.
    #[structopt(short = "s", long, default_value = "65535")]
    snap_len: i32,

    /// List device, view device status.
    #[structopt(short = "l", long)]
    list_device: bool,

    /// Record raw packet.
    #[structopt(short = "r", long)]
    raw: bool,

    /// Opens a capture handle for a device.
    #[structopt(short = "d", long = "dev", default_value = "")]
    device: String,

    /// Set the package magnification, by default, the package does not do
    /// enlargement processing, and it only takes effect when this parameter is greater than 1.
    #[structopt(short = "x", long = "amplify", default_value = "1")]
    amplify: usize,

    /// Save matched packets in pcap format to pcap file, if there is
    /// no matching rule, the default is to cap the full package.
    #[structopt(short = "o", long, default_value = "/tmp/0.pcap")]
    output: String,

    /// Specify a BPF filter, only match the target package.
    #[structopt(short = "M", long, default_value = "")]
    matcher: String,

    /// Files is read packet stream from pcap format files.
    #[structopt(name = "FILE", parse(from_os_str))]
    files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Config {
    opt: Opt,
}

impl Config {
    pub fn new() -> Config {
        Config {
            opt: Opt::from_args(),
        }
    }

    pub fn get_promisc(&self) -> bool {
        self.opt.promisc
    }

    pub fn list_device(&self, devs: Vec<Device>) -> Vec<Device> {
        if self.opt.list_device {
            device_detail(devs);
            exit(0)
        }
        devs
    }

    pub fn get_device(&self, devs: Vec<Device>) -> Option<Device> {
        for dev in devs {
            if dev.name == self.opt.device {
                return Some(dev)
            }
        }
        None
    }

    pub fn get_device_name(&self) -> String {
        self.opt.device.clone()
    }

    pub fn get_amplify(&self) -> usize {
        self.opt.amplify
    }

    pub fn get_files(&self) -> Vec<PathBuf> {
        self.opt.files.clone()
    }

    pub fn get_output(&self) -> String {
        self.opt.output.clone()
    }

    pub fn get_raw(&self) -> bool {
        self.opt.raw
    }

    pub fn get_snap_len(&self) -> i32 {
        self.opt.snap_len
    }

    pub fn get_ignore_case(&self) -> bool {
        self.opt.ignore_case
    }

    pub fn get_multiline(&self) -> bool {
        self.opt.multiline
    }

    pub fn get_pattern(&self) -> String {
        self.opt.pattern.clone()
    }

    pub fn get_matcher(&self) -> String {
        self.opt.matcher.clone()
    }

    pub fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct Runner {
    config: Config,
    regex: Regex,
    dev: Option<Device>,
    core: Runtime,
    task: Runtime
}

impl Runner {
    pub fn new(c: Config) -> Result<Self, Error> {
        c.validate().unwrap_or_else(|_err| panic!("config error"));

        let devs = c.list_device(Device::list().unwrap());
        let mut dev = c.get_device(devs);
        match dev {
            None => {
                if !c.get_device_name().is_empty() {
                    dev = Device::lookup().unwrap();
                    println!("The device ({:?}) does not exist, the main device ({}) is used by default.", c.get_device_name(), dev.as_ref().unwrap().name.as_str().yellow().bold())
                }
            }
            _ => {}
        }
        let regex= RegexBuilder::new()
            .caseless(c.get_ignore_case())
            .multi_line(c.get_multiline())
            .build(c.get_pattern().as_str()).unwrap();
        let a = c.get_amplify();
        Ok(Runner{
            config: c,
            regex,
            dev,
            core: Builder::new_current_thread()
                .thread_name("core")
                .enable_all()
                .build()
                .unwrap(),
            task: Builder::new_multi_thread()
                .thread_name("task")
                .worker_threads(a)
                .enable_all()
                .build()
                .unwrap()
        })
    }

    pub fn run(&mut self) {
        let (tx, mut rx) = broadcast::channel::<Log>(CHANNEL_CAPACITY);
        if self.config.get_amplify() > 1 {
            self.task.spawn(back_device(self.dev.clone().unwrap(), rx));
        } else {
            self.task.spawn(printer(self.regex.clone(), rx));
        }

        let dev = self.dev.clone();
        let files = self.config.get_files();
        let c = self.config.clone();
        self.core.block_on(async {
            let mut num = -1;
            if !dev.is_none() || files.len() > 0 {
                num = files.len() as isize;
            }
            match get_status(num as isize) {
                Status::Online => {
                    println!("{}", "waiting for packet from network device ...".green().bold());
                    let mut cap = Capture::from_device(dev.unwrap()).unwrap()
                        .promisc(!c.get_promisc())
                        .snaplen(c.get_snap_len())
                        .open()
                        .unwrap()
                        .setnonblock()
                        .unwrap();
                    if !c.get_matcher().is_empty() {
                        cap.filter(c.get_matcher().as_str(), true).unwrap();
                    }
                    let mut file = cap.savefile(c.get_output()).unwrap();
                    while let result = cap.next_packet() {
                        match result {
                            Ok(packet) => {
                                let r = tx.send(Log::from_packet(packet.clone()));
                                match r {
                                    Err(e) => {
                                        println!("online send {:?}", e.to_string());
                                        exit(0)
                                    }
                                    _ => {}
                                };
                                if c.get_raw() {
                                    file.write(&packet);
                                }
                            }
                            Err(e) => {
                                match e {
                                    pcap::Error::TimeoutExpired => {
                                        continue;
                                    }
                                    _ => {}
                                }
                                println!("cap packet error {:?}", e);
                                exit(0)
                            }
                        }
                    }
                }
                Status::Offline => {
                    println!("{}", "waiting for packet from file ...".yellow().bold());
                    for file in files {
                        let mut cap = Capture::from_file(file).unwrap();
                        while let Ok(packet) = cap.next_packet() {
                            let r = tx.send(Log::from_packet(packet));
                            match r {
                                Err(e) => {
                                    println!("offline send {:?}", e.to_string());
                                    exit(0)
                                }
                                _ => {}
                            };
                        }
                    }
                }
                _ => {
                    println!("{}", "waiting for data from stdin ...".cyan().bold());
                    let stdin = io::stdin();
                    while let Some(line)= stdin.lock().lines().next() {
                        match line {
                            Ok(s) => {
                                let r = tx.send(Log::from_data(s));
                                match r {
                                    Err(e) => {
                                        println!("pipeline send {:?}", e.to_string());
                                        exit(0)
                                    }
                                    _ => {}
                                };
                            }
                            Err(e) => {
                                println!("stdin error {:?}", e);
                                continue;
                            }
                        }
                    }
                }
            }
        })
    }

    pub fn exit(mut self) {
        self.task.shutdown_background();
        self.core.shutdown_background()
    }
}

#[derive(Clone)]
pub struct Log {
    raw: bool,
    time: String,
    cap_time: String,
    data: String,
    raw_data: Vec<u8>
}

impl Default for Log {
    fn default() -> Self {
        Log{
            raw: true,
            time: Default::default(),
            cap_time: Default::default(),
            data: String::default(),
            raw_data: vec![]
        }
    }
}

impl Log {
    pub fn from_data(mut s: String) -> Log {
        let raw = false;
        s = format!("{}, raw: {}", s, raw);
        Log{
            raw,
            time: Default::default(),
            cap_time: Default::default(),
            data: s,
            raw_data: vec![]
        }
    }

    pub fn from_packet(p: Packet) -> Log {
        let mut log = Log::default();
        log.raw_data = p.data.to_vec();
        log.time = Local::now().to_string();
        log.cap_time = NaiveDateTime::from_timestamp(p.header.ts.tv_sec, p.header.ts.tv_usec as u32)
            .and_local_timezone(Local)
            .unwrap()
            .to_string();
        log.data = format!("{}, {}", log.time, log.cap_time);

        match SlicedPacket::from_ethernet(&p.data) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                if value.link != None {
                    log.data = format!("{}, {} {}", log.data, DATA_LINK_LAYER, String::from(DataLink(value.link.unwrap().to_header())));
                }
                if value.vlan != None {
                    log.data = format!("{}, {} {:?}", log.data, DATA_LINK_LAYER, value.vlan);
                }
                if value.ip != None {
                    match value.ip {
                        Some(ip) => {
                            match ip {
                                InternetSlice::Ipv4(h, e) => {
                                    log.data = format!("{}, {} {}", log.data, NETWORK_LAYER, String::from(Ipv4header(h.to_header())));
                                }
                                InternetSlice::Ipv6(h, e) => {
                                    log.data = format!("{}, {} {}", log.data, NETWORK_LAYER, String::from(Ipv6header(h.to_header())));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if value.transport != None {
                    match value.transport {
                        Some(ts) => {
                            match ts {
                                TransportSlice::Icmpv4(icmp4) => {
                                    log.data = format!("{}, {} {}", log.data, TRANSPORT_LAYER, String::from(ICMPv4header(icmp4.header())));
                                }
                                TransportSlice::Icmpv6(icmp6) => {
                                    log.data = format!("{}, {} {}", log.data, TRANSPORT_LAYER, String::from(ICMPv6header(icmp6.header())));
                                }
                                TransportSlice::Udp(udp) => {
                                    log.data = format!("{}, {} {}", log.data, TRANSPORT_LAYER, String::from(UDPHeader(udp.to_header())));
                                }
                                TransportSlice::Tcp(tcp) => {
                                    log.data = format!("{}, {} {}", log.data, TRANSPORT_LAYER, String::from(TCPHeader(tcp.to_header())));
                                }
                                TransportSlice::Unknown(un) => {
                                    println!("unknown {:?}", un.to_string())
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        log
    }
}

impl TryFrom<Log> for String {
    type Error = Error;

    fn try_from(log: Log) -> Result<Self, Self::Error> {
        Ok(log.data)
    }
}

struct DataLink(Ethernet2Header);

impl From<DataLink> for String {
    fn from(h: DataLink) -> Self {
        format!(r#"{{ dest_mac: {}, src_mac: {}, type: {:?} }}"#,
                MacAddr6::from(h.0.destination).to_string(),
                MacAddr6::from(h.0.source).to_string(),
                EtherType::from_u16(h.0.ether_type).unwrap())
    }
}

struct Ipv4header(Ipv4Header);

impl From<Ipv4header> for String {
    fn from(h: Ipv4header) -> Self {
        format!(r#"{{ dest_ip: {}, src_ip: {}, protocol: {:?}, header_checksum: {}, differentiated_services_code_point: {}, explicit_congestion_notification: {}, payload_len: {}, identification: {}, dont_fragment: {}, more_fragments: {}, fragments_offset: {}, time_to_live: {} }}"#,
                Ipv4Addr::from(h.0.destination).to_string(), Ipv4Addr::from(h.0.source).to_string(), Protocol::from(h.0.protocol).unwrap(), h.0.header_checksum, h.0.differentiated_services_code_point,
                h.0.explicit_congestion_notification, h.0.payload_len, h.0.identification, h.0.dont_fragment, h.0.more_fragments, h.0.fragments_offset, h.0.time_to_live)
    }
}

struct Ipv6header(Ipv6Header);

impl From<Ipv6header> for String {
    fn from(h: Ipv6header) -> Self {
        format!(r#"{{ dest_ip: {}, src_ip: {}, traffic_class: {}, flow_label: {}, payload_length: {}, hop_limit: {}, next_header: {} }}"#,
                Ipv6Addr::from(h.0.destination).to_string(), Ipv6Addr::from(h.0.source).to_string(), h.0.traffic_class,
                h.0.flow_label, h.0.payload_length, h.0.hop_limit, h.0.next_header)
    }
}

struct ICMPv4header(Icmpv4Header);

impl From<ICMPv4header> for String {
    fn from(h: ICMPv4header) -> Self {
        format!(r#"{{ type: {:?}, checksum: {} }}"#, h.0.icmp_type, h.0.checksum)
    }
}

struct ICMPv6header(Icmpv6Header);

impl From<ICMPv6header> for String {
    fn from(h: ICMPv6header) -> Self {
        format!(r#"{{ type: {:?}, checksum: {} }}"#, h.0.icmp_type, h.0.checksum)
    }
}

struct TCPHeader(TcpHeader);

impl From<TCPHeader> for String {
    fn from(h: TCPHeader) -> Self {
        format!(r#"{{ dest_port: {}, src_port: {}, sequence_number: {}, acknowledgment_number: {}, data_offset: {}, ns: {}, fin: {}, syn: {}, rst: {}, psh: {}, ack: {}, urg: {}, ece: {}, cwr: {}, window_size: {}, checksum: {}, urgent_pointer: {} }}"#,
                h.0.destination_port, h.0.source_port, h.0.sequence_number, h.0.acknowledgment_number, h.0.data_offset(),
                h.0.ns, h.0.fin, h.0.syn, h.0.rst, h.0.psh, h.0.ack, h.0.urg, h.0.ece, h.0.cwr, h.0.window_size, h.0.checksum, h.0.urgent_pointer)
    }
}

struct UDPHeader(UdpHeader);

impl From<UDPHeader> for String {
    fn from(h: UDPHeader) -> Self {
        format!(r#"{{ dest_port: {}, src_port: {}, length: {}, checksum: {} }}"#,
                h.0.destination_port, h.0.source_port, h.0.length, h.0.checksum)
    }
}

async fn back_device(dev: Device, mut rx: Receiver<Log>) {
    let mut cap = Capture::from_device(dev).unwrap()
        .open()
        .unwrap();
    while let log = rx.recv().await {
        match log {
            Ok(l) => {
                match cap.sendpacket(l.raw_data) {
                    Err(e) => {
                        println!("send packet error {:?}", e);
                        exit(0)
                    }
                    _ => {}
                };
            }
            Err(re) => {
                match re {
                    RecvError::Closed => {
                        println!("recv {:?}", re.to_string());
                        exit(0)
                    }
                    RecvError::Lagged(n) => {
                        if n > MAX_LAGGED as u64 {
                            println!("too much message lag({:?}), please increase the number of threads.", n);
                            exit(0)
                        }
                        continue;
                    }
                }
            }
        };
    }
}

async fn printer(matcher: Regex, mut rx: Receiver<Log>) {
    while let log = rx.recv().await {
        match log {
            Ok(l) => {
                let raw = l.raw;
                let ls = String::try_from(l).unwrap();
                let text = ls.as_bytes();
                match matcher.find(text).unwrap() {
                    Some(m) => {
                        if raw {
                            println!("{}", SPLITTER);
                        }
                        println!("{}", ls.as_str());
                    }
                    _ => {}
                };
            }
            Err(re) => {
                match re {
                    RecvError::Closed => {
                        println!("recv {:?}", re.to_string());
                        exit(0)
                    }
                    RecvError::Lagged(n) => {
                        if n > MAX_LAGGED as u64 {
                            println!("too much message lag({:?}), please increase the number of threads.", n);
                            exit(0)
                        }
                        continue;
                    }
                }
            }
        };
    }
}

fn get_status(num: isize) -> Status {
    if num >= 0 {
        return match num {
            0 => {
                Status::Online
            }
            _ => {
                Status::Offline
            }
        }
    }
    Status::Pipeline
}

fn device_detail(devs: Vec<Device>) {
    println!("{:<13} {:<43} {:<73} {:<20} {:<28}", "DEVICE".bold(), "ADDRS".bold(), "MASKS".bold(), "BROADCASTS".bold(), "STATUS".bold());
    for dev in devs {
        let mut addr = String::new();
        let mut mask = String::new();
        let mut broadcast  = String::new();
        let addr_n = dev.addresses.len();
        if addr_n > 0 {
            let mut addrs = Vec::new();
            let mut masks = Vec::new();
            let mut broadcasts = Vec::new();
            for addr in dev.addresses {
                addrs.push(addr.addr.to_string());
                match addr.netmask {
                    Some(m) => {
                        masks.push(m.to_string())
                    }
                    _ => {}
                }
                match addr.broadcast_addr {
                    Some(b) => {
                        broadcasts.push(b.to_string())
                    }
                    _ => {}
                }
            }
            mask = masks.join("/");
            broadcast = broadcasts.join("/");
            addr = addrs.join("/");
        }
        let status = format!("{:?}", dev.flags.if_flags);
        if addr_n > 0 && !dev.flags.if_flags.is_empty() {
            println!("{:<13} {:<43} {:<73} {:<20} {:<28}", dev.name, addr, mask, broadcast, status.as_str().green());
            continue
        }
        println!("{:<13} {:<43} {:<73} {:<20} {:<28}", dev.name, addr, mask, broadcast, status)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use pcre2::bytes::{Match, RegexBuilder};
    use crate::pf::{Error, get_status, Status};

    #[test]
    fn get_status_works_for_run() -> Result<(), Error> {
        let tests = vec![-1, 0, 1];
        for test in tests {
            let s = get_status(test);
            if test < 0 {
                assert_eq!(s, Status::Pipeline);
            }
            if test == 0 {
                assert_eq!(s, Status::Online);
            }
            if test > 0 {
                assert_eq!(s, Status::Offline);
            }
        }
        Ok(())
    }

    #[test]
    fn matcher_works_for_packet_and_data() -> Result<(), Error> {
        let mut tests = HashMap::new();
        tests.insert("abc", true);
        tests.insert("123", false);
        tests.insert("bbs789", true);
        let regex= RegexBuilder::new()
            .caseless(true)
            .multi_line(true)
            .build("b").unwrap();
        for (k,v) in tests {
            let r = regex.find(k.as_bytes()).unwrap();
            match r {
                Some(m) => {
                    assert_eq!(v, true);
                }
                None => {
                    assert_eq!(v, false);
                }
            }
        }
        Ok(())
    }
}
