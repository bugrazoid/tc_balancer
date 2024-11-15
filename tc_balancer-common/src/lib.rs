#![no_std]

pub const CONFIG_MAP_LEN: u32 = 8;

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
