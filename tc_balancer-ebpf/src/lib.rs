#![no_std]

// This file exists to enable the library target.

#[allow(non_camel_case_types)]
pub mod bindings;

use core::mem;

use bindings::{ethhdr, iphdr};

pub const IPPROTO_TCP: u8 = 0x06;
pub const IPPROTO_UDP: u8 = 0x11;
/// Ipv4
pub const ETH_P_IP: u16 = 0x0800u16.to_be();
/// Ipv6
pub const ETH_P_IPV6: u16 = 0x086ddu16.to_be();

pub const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
pub const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
pub const TCP_HDR_LEN: usize = mem::size_of::<bindings::tcphdr>();
