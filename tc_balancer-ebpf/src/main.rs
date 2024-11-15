#![no_std]
#![no_main]

mod bindings;

use core::{ffi::c_long, net::Ipv4Addr};

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, LruHashMap},
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use bindings::{ethhdr, iphdr, tcphdr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
};
use tc_balancer_ebpf::{
    parse_packet, ETH_HDR_LEN, ETH_HDR_OFFSET, ETH_P_IP, IPPROTO_TCP, IP_HDR_LEN, IP_HDR_OFFSET,
    TCP_HDR_LEN, TCP_HDR_OFFSET,
};

#[map(name = "CONFIG")]
static mut CONFIG: HashMap<u16, Ipv4Addr> = HashMap::with_max_entries(10, 0);

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

fn try_tc_balancer(ctx: TcContext, direction: &str) -> Result<i32, c_long> {
    let p = parse_packet(&ctx).ok_or(1)?;

    debug!(
        &ctx,
        "{}, received a packet {}:{} -> {}:{}",
        direction,
        p.src.ip,
        p.src.port.inner(),
        p.dst.ip,
        p.dst.port.inner()
    );

    if p.src.port == 8081.into() || p.dst.port == 8080.into() {
        info!(
            &ctx,
            "{}, received a packet {}:{} -> {}:{}",
            direction,
            p.src.ip,
            p.src.port.inner(),
            p.dst.ip,
            p.dst.port.inner()
        );
    }

    if p.dst.port == 8080.into() {
        p.tcp.dest = 8081u16.to_be();
        return Ok(TC_ACT_PIPE);
    }

    if p.src.port == 8081.into() {
        p.tcp.source = 8080u16.to_be();
        return Ok(TC_ACT_PIPE);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
