#![no_std]

// This file exists to enable the library target.

#[allow(non_camel_case_types)]
pub mod bindings;

use core::{mem, net::Ipv4Addr};

use aya_ebpf::{programs::TcContext, EbpfContext};
use aya_log_ebpf::debug;
use bindings::{ethhdr, iphdr, tcphdr};
use network_types::{eth::EtherType, ip::IpProto};
use tc_balancer_common::Port;

pub const IPPROTO_TCP: u8 = 0x06;
pub const IPPROTO_UDP: u8 = 0x11;
/// Ipv4
pub const ETH_P_IP: u16 = 0x0800u16.to_be();
/// Ipv6
pub const ETH_P_IPV6: u16 = 0x086ddu16.to_be();

pub const ETH_HDR_OFFSET: usize = 0;
pub const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

pub const IP_HDR_OFFSET: usize = ETH_HDR_LEN;
pub const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

pub const TCP_HDR_OFFSET: usize = IP_HDR_OFFSET + IP_HDR_LEN;
pub const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

pub const INGRESS: &'static str = "ingress";
pub const EGRESS: &'static str = "egress";

pub struct IngressPacket<'a>(ParsedPacket<'a>);

impl<'a> IngressPacket<'a> {
    pub fn new(parsed_packet: ParsedPacket<'a>) -> Self {
        Self(parsed_packet)
    }

    pub fn remote_ip(&self) -> Ipv4Addr {
        self.0.src.ip
    }

    pub fn remote_port(&self) -> Port {
        self.0.src.port
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.0.dst.ip
    }

    pub fn local_port(&self) -> Port {
        self.0.dst.port
    }

    pub fn set_local_port(&mut self, port: Port) {
        self.0.dst.port = port;
        self.0.tcp.dest = port.inner().to_be();
    }
}

impl<'a> From<ParsedPacket<'a>> for EgressPacket<'a> {
    fn from(parsed_packet: ParsedPacket<'a>) -> Self {
        EgressPacket::new(parsed_packet)
    }
}

pub struct EgressPacket<'a>(ParsedPacket<'a>);

impl<'a> EgressPacket<'a> {
    pub fn new(parsed_packet: ParsedPacket<'a>) -> Self {
        Self(parsed_packet)
    }

    pub fn remote_ip(&self) -> Ipv4Addr {
        self.0.dst.ip
    }

    pub fn remote_port(&self) -> Port {
        self.0.dst.port
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.0.src.ip
    }

    pub fn local_port(&self) -> Port {
        self.0.src.port
    }

    pub fn set_local_port(&mut self, port: Port) {
        self.0.src.port = port;
        self.0.tcp.source = port.inner().to_be();
    }
}

impl<'a> From<ParsedPacket<'a>> for IngressPacket<'a> {
    fn from(parsed_packet: ParsedPacket<'a>) -> Self {
        IngressPacket::new(parsed_packet)
    }
}

pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: Port,
}

pub struct ParsedPacket<'a> {
    pub eth: &'a ethhdr,
    pub ip: &'a iphdr,
    pub tcp: &'a mut tcphdr,
    pub protocol: EtherType,
    pub src: Endpoint,
    pub dst: Endpoint,
}

pub fn parse_packet<'a, CTX: Data + EbpfContext>(ctx: &CTX) -> Option<ParsedPacket<'a>> {
    let eth = ptr_at::<ethhdr, _>(ctx, ETH_HDR_OFFSET)?;
    let eth = unsafe { &(*eth) };

    if eth.h_proto != EtherType::Ipv4 as u16 {
        debug!(
            ctx,
            "drop packet because it is not ipv4: 0x{:x}",
            u16::from_be(eth.h_proto)
        );
        return None;
    }

    let ip = ptr_at::<iphdr, _>(ctx, IP_HDR_OFFSET)?;
    let ip = unsafe { &(*ip) };

    if ip.protocol != IpProto::Tcp as u8 {
        debug!(ctx, "received a Ipv4 packet not tcp: {}", ip.protocol);
        return None;
    }

    let addrs = unsafe { ip.__bindgen_anon_1.addrs };

    let src_addr = Ipv4Addr::from(u32::from_be(addrs.saddr));
    let dst_addr = Ipv4Addr::from(u32::from_be(addrs.daddr));

    let tcp = ptr_at_mut::<tcphdr, _>(ctx, TCP_HDR_OFFSET)?;
    let tcp = unsafe { &mut (*tcp) };

    let src_port = u16::from_be(tcp.source);
    let dst_port = u16::from_be(tcp.dest);

    Some(ParsedPacket {
        eth,
        ip,
        tcp: tcp,
        protocol: EtherType::Ipv4,
        src: Endpoint {
            ip: src_addr,
            port: src_port.into(),
        },
        dst: Endpoint {
            ip: dst_addr,
            port: dst_port.into(),
        },
    })
}

pub trait Data {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;
}

impl Data for TcContext {
    fn data(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

#[inline(always)]
pub fn ptr_at<T, CTX: Data>(ctx: &CTX, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T, CTX: Data>(ctx: &CTX, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T, CTX>(ctx, offset)?;
    Some(ptr as *mut T)
}
