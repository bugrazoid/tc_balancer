#![no_std]
#![no_main]

use core::error;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, LruHashMap},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use tc_balancer_common::{Config, Port, RedirectEgressId, CONFIG_MAP_LEN, REDIRECT_EGRESS_MAP_LEN};
use tc_balancer_ebpf::{parse_packet, ParsedPacket, EGRESS, INGRESS};

#[map(name = "CONFIG")]
static mut CONFIG: HashMap<Port, Config> = HashMap::with_max_entries(CONFIG_MAP_LEN, 0);

#[map(name = "REDIRECT_EGRESS")]
static mut REDIRECT_EGRESS: LruHashMap<RedirectEgressId, Port> =
    LruHashMap::with_max_entries(REDIRECT_EGRESS_MAP_LEN, 0);

#[classifier]
pub fn tc_balancer_ingress(ctx: TcContext) -> i32 {
    match try_tc_balancer(&ctx, "ingress") {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn tc_balancer_egress(ctx: TcContext) -> i32 {
    match try_tc_balancer(&ctx, "egress") {
        Ok(ret) => ret,
        Err(_) => {
            error!(&ctx, "error");
            TC_ACT_PIPE
        }
    }
}

fn try_tc_balancer(ctx: &TcContext, direction: &str) -> Result<i32, ()> {
    let p = parse_packet(ctx).ok_or(())?;

    debug!(
        ctx,
        "{}: received a packet {}:{} -> {}:{}",
        direction,
        p.src.ip,
        p.src.port.inner(),
        p.dst.ip,
        p.dst.port.inner()
    );

    if p.src.port == 8081.into() || p.dst.port == 8080.into() {
        info!(
            ctx,
            "{}: packet {}:{} -> {}:{}",
            direction,
            p.src.ip,
            p.src.port.inner(),
            p.dst.ip,
            p.dst.port.inner()
        );
    }

    match direction {
        "ingress" => process_ingress(ctx, p)?,
        "egress" => process_egress(ctx, p)?,
        _ => TC_ACT_PIPE,
    };

    Ok(TC_ACT_PIPE)
}

fn process_ingress(ctx: &TcContext, ingress_packet: ParsedPacket) -> Result<i32, ()> {
    if let Some(config) = unsafe { CONFIG.get(&ingress_packet.dst.port) } {
        info!(
            ctx,
            "{}: redirect dst port {} => {}",
            INGRESS,
            ingress_packet.dst.port.inner(),
            config.redirect_port.inner()
        );

        ingress_packet.tcp.dest = config.redirect_port.inner().to_be();

        let key = RedirectEgressId::new(
            ingress_packet.src.ip,
            ingress_packet.src.port,
            ingress_packet.dst.ip,
        );
        info!(
            ctx,
            "{}:{} -> {}",
            key.src_addr,
            key.src_port.inner(),
            key.dst_addr
        );
        unsafe { REDIRECT_EGRESS.insert(&key, &config.redirect_port, 0) }.map_err(|_| ())?;

        return Ok(TC_ACT_PIPE);
    }

    debug!(
        ctx,
        "{}: no config for port {}",
        EGRESS,
        ingress_packet.dst.port.inner()
    );

    Ok(TC_ACT_PIPE)
}

fn process_egress(ctx: &TcContext, egress_packet: ParsedPacket) -> Result<i32, ()> {
    let key = RedirectEgressId::new(
        egress_packet.dst.ip,
        egress_packet.dst.port,
        egress_packet.src.ip,
    );

    if let Some(redirect_port) = unsafe { REDIRECT_EGRESS.get(&key) } {
        info!(
            ctx,
            "{}:{} -> {}",
            key.src_addr,
            key.src_port.inner(),
            key.dst_addr
        );
        egress_packet.tcp.source = redirect_port.inner().to_be();
        // return Ok(TC_ACT_PIPE);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
