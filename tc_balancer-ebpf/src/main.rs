#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, LruHashMap},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use tc_balancer_common::{
    Config, Port, RedirectLocalPortKey, CONFIG_MAP_LEN, REDIRECT_EGRESS_MAP_LEN,
};
use tc_balancer_ebpf::{parse_packet, EgressPacket, IngressPacket, EGRESS, INGRESS};

#[map(name = "CONFIG")]
static mut CONFIG: HashMap<Port, Config> = HashMap::with_max_entries(CONFIG_MAP_LEN, 0);

#[map(name = "REDIRECT_EGRESS")]
static mut REDIRECT_EGRESS: LruHashMap<RedirectLocalPortKey, Port> =
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
        "ingress" => process_ingress(ctx, p.into())?,
        "egress" => process_egress(ctx, p.into())?,
        _ => TC_ACT_PIPE,
    };

    Ok(TC_ACT_PIPE)
}

fn process_ingress(ctx: &TcContext, mut packet: IngressPacket) -> Result<i32, ()> {
    if let Some(config) = unsafe { CONFIG.get(&packet.local_port()) } {
        info!(
            ctx,
            "{}: redirect dst port {} => {}",
            INGRESS,
            packet.local_port().inner(),
            config.redirect_port.inner()
        );

        packet.set_local_port(config.redirect_port);

        let key =
            RedirectLocalPortKey::new(packet.remote_ip(), packet.remote_port(), packet.local_ip());
        info!(
            ctx,
            "{}:{} -> {}",
            key.remote_ip,
            key.remote_port.inner(),
            key.local_ip
        );
        unsafe { REDIRECT_EGRESS.insert(&key, &config.redirect_port, 0) }.map_err(|_| ())?;

        return Ok(TC_ACT_PIPE);
    }

    debug!(
        ctx,
        "{}: no config for port {}",
        EGRESS,
        packet.local_port().inner()
    );

    Ok(TC_ACT_PIPE)
}

fn process_egress(ctx: &TcContext, mut packet: EgressPacket) -> Result<i32, ()> {
    let key =
        RedirectLocalPortKey::new(packet.remote_ip(), packet.remote_port(), packet.local_ip());

    if let Some(redirect_port) = unsafe { REDIRECT_EGRESS.get(&key) } {
        info!(
            ctx,
            "{}:{} -> {}",
            key.remote_ip,
            key.remote_port.inner(),
            key.local_ip
        );
        packet.set_local_port(*redirect_port);
        // return Ok(TC_ACT_PIPE);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
