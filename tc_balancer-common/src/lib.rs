#![no_std]

use core::net::Ipv4Addr;

pub const CONFIG_MAP_LEN: u32 = 8;
pub const REDIRECT_EGRESS_MAP_LEN: u32 = 8;

#[derive(PartialEq, Clone, Copy)]
pub struct Port(u16);

impl Port {
    pub fn new(port: u16) -> Self {
        Self(port)
    }
    pub fn inner(&self) -> u16 {
        self.0
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Port {}

impl From<u16> for Port {
    fn from(value: u16) -> Self {
        Port(value)
    }
}

#[derive(Clone, Copy)]
pub struct Config {
    pub redirect_port: Port,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

#[derive(Clone, Copy)]
pub struct RedirectEgressId {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: Port,
}

impl RedirectEgressId {
    pub fn new(src_addr: Ipv4Addr, src_port: Port, dst_addr: Ipv4Addr) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RedirectEgressId {}
