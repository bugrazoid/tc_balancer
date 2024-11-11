#![no_std]
#![no_main]

mod bindings;

use core::{ffi::c_long, net::Ipv4Addr};

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::{debug, info};
use bindings::{ethhdr, iphdr, tcphdr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
};
use tc_balancer_ebpf::{
    tc::{ptr_at, ptr_at_mut},
    ETH_HDR_LEN, ETH_HDR_OFFSET, ETH_P_IP, IPPROTO_TCP, IP_HDR_LEN, IP_HDR_OFFSET, TCP_HDR_LEN,
    TCP_HDR_OFFSET,
};

#[classifier]
pub fn tc_balancer_ingress(ctx: TcContext) -> i32 {
    match try_tc_balancer(ctx, "ingress") {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn tc_balancer_egress(ctx: TcContext) -> i32 {
    match try_tc_balancer(ctx, "egress") {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_tc_balancer(mut ctx: TcContext, direction: &str) -> Result<i32, c_long> {
    let eth = ptr_at::<ethhdr>(&ctx, ETH_HDR_OFFSET).ok_or(1)?;
    let eth = unsafe { &(*eth) };

    if eth.h_proto != EtherType::Ipv4 as u16 {
        debug!(
            &ctx,
            "drop packet because it is not ipv4: 0x{:x}",
            u16::from_be(eth.h_proto)
        );
        return Ok(TC_ACT_PIPE);
    }

    let ip = ptr_at::<iphdr>(&ctx, IP_HDR_OFFSET).ok_or(2)?;
    let ip = unsafe { &(*ip) };

    if ip.protocol != IpProto::Tcp as u8 {
        debug!(&ctx, "received a Ipv4 packet not tcp: {}", ip.protocol);
        return Ok(TC_ACT_PIPE);
    }

    let addrs = unsafe { ip.__bindgen_anon_1.addrs };

    let src_addr = Ipv4Addr::from(u32::from_be(addrs.saddr));
    let dst_addr = Ipv4Addr::from(u32::from_be(addrs.daddr));

    let tcp = ptr_at_mut::<tcphdr>(&ctx, TCP_HDR_OFFSET).ok_or(3)?;
    let tcp = unsafe { &mut (*tcp) };

    let src_port = u16::from_be(tcp.source);
    let dst_port = u16::from_be(tcp.dest);

    debug!(
        &ctx,
        "{}, received a packet {}:{} -> {}:{}", direction, src_addr, src_port, dst_addr, dst_port
    );

    if src_port == 8081 || dst_port == 8080 {
        info!(
            &ctx,
            "{}, received a packet {}:{} -> {}:{}",
            direction,
            src_addr,
            src_port,
            dst_addr,
            dst_port
        );
    }

    if dst_port == 8080 {
        tcp.dest = 8081u16.to_be();
        return Ok(TC_ACT_PIPE);
    }

    if src_port == 8081 {
        tcp.source = 8080u16.to_be();
        return Ok(TC_ACT_PIPE);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
