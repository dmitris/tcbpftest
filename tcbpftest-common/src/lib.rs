#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub len: u32,       // packet length
    pub ctx_len: u32,   // skb length
    pub src_addr: u32,  // ipv4 source IP address
    pub dest_addr: u32, // ipv4 destination IP address
    pub eth_proto: u32, // Ethernet protocol
    pub ip_proto: u32,  // ipv4 protocol
    pub sport: u32,     // TCP or UDP remote port (sport for ingress)
    pub dport: u32,     // TCP or UDP local port (dport for ingress)
    pub udp_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
