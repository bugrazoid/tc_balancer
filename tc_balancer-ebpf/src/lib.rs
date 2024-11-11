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

pub const ETH_HDR_OFFSET: usize = 0;
pub const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

pub const IP_HDR_OFFSET: usize = ETH_HDR_LEN;
pub const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

pub const TCP_HDR_OFFSET: usize = IP_HDR_OFFSET + IP_HDR_LEN;
pub const TCP_HDR_LEN: usize = mem::size_of::<bindings::tcphdr>();

pub mod tc {
    use core::mem;

    use aya_ebpf::programs::TcContext;

    #[inline(always)]
    pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Option<*const T> {
        let start = ctx.data();
        let end = ctx.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return None;
        }

        Some((start + offset) as *const T)
    }

    #[inline(always)]
    pub fn ptr_at_mut<T>(ctx: &TcContext, offset: usize) -> Option<*mut T> {
        let ptr = ptr_at::<T>(ctx, offset)?;
        Some(ptr as *mut T)
    }
}
