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
use tc_balancer_ebpf::{ETH_HDR_LEN, ETH_P_IP, IPPROTO_TCP, IP_HDR_LEN, TCP_HDR_LEN};

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
    const ETH_HDR_OFFSET: usize = 0;
    let ethhrd: ethhdr = ctx.load(ETH_HDR_OFFSET)?;

    if ethhrd.h_proto != EtherType::Ipv4 as u16 {
        debug!(
            &ctx,
            "drop packet because it is not ipv4: 0x{:x}",
            u16::from_be(ethhrd.h_proto)
        );
        return Ok(TC_ACT_PIPE);
    }

    const IP_HDR_OFFSET: usize = ETH_HDR_LEN;
    let ip: iphdr = ctx.load(IP_HDR_OFFSET)?;

    if ip.protocol != IpProto::Tcp as u8 {
        debug!(&ctx, "received a Ipv4 packet not tcp: {}", ip.protocol);
        return Ok(TC_ACT_PIPE);
    }

    let addrs = unsafe { ip.__bindgen_anon_1.addrs };

    let src_addr = Ipv4Addr::from(u32::from_be(addrs.saddr));
    let dst_addr = Ipv4Addr::from(u32::from_be(addrs.daddr));

    const TCP_HDR_OFFSET: usize = IP_HDR_OFFSET + IP_HDR_LEN;
    let mut tcp = ctx.load::<tcphdr>(TCP_HDR_OFFSET)?;

    let src_port = u16::from_be(tcp.source);
    let dst_port = u16::from_be(tcp.dest);

    debug!(
        &ctx,
        "{}, received a packet {}:{} -> {}:{}", direction, src_addr, src_port, dst_addr, dst_port
    );

    if src_port == 8080 || dst_port == 8080 {
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
        ctx.store(TCP_HDR_OFFSET, &tcp, 0)?;
        return Ok(TC_ACT_PIPE);
    }

    if src_port == 8081 {
        tcp.source = 8080u16.to_be();
        ctx.store(TCP_HDR_OFFSET, &tcp, 0)?;
        return Ok(TC_ACT_PIPE);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
