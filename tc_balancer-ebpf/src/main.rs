#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, LruHashMap},
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use tc_balancer_common::{Config, Port, CONFIG_MAP_LEN};
use tc_balancer_ebpf::{parse_packet, ParsedPacket, EGRESS, INGRESS};

#[map(name = "CONFIG")]
static mut CONFIG: HashMap<Port, Config> = HashMap::with_max_entries(CONFIG_MAP_LEN, 0);

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

fn try_tc_balancer(ctx: TcContext, direction: &str) -> Result<i32, ()> {
    let p = parse_packet(&ctx).ok_or(())?;

    debug!(
        &ctx,
        "{}: received a packet {}:{} -> {}:{}",
        direction,
        p.src.ip,
        p.src.port.inner(),
        p.dst.ip,
        p.dst.port.inner()
    );

    if p.src.port == 8081.into() || p.dst.port == 8080.into() {
        info!(
            &ctx,
            "{}: received a packet {}:{} -> {}:{}",
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

fn process_ingress(ctx: TcContext, p: ParsedPacket) -> Result<i32, ()> {
    if let Some(config) = unsafe { CONFIG.get(&p.dst.port) } {
        info!(
            &ctx,
            "{}: config for port {} is: {}",
            INGRESS,
            p.dst.port.inner(),
            config.redirect_port.inner()
        );

        p.tcp.dest = config.redirect_port.inner().to_be();
        return Ok(TC_ACT_PIPE);
    }

    debug!(
        &ctx,
        "{}: no config for port {}",
        EGRESS,
        p.dst.port.inner()
    );

    Ok(TC_ACT_PIPE)
}

fn process_egress(ctx: TcContext, p: ParsedPacket) -> Result<i32, ()> {
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
