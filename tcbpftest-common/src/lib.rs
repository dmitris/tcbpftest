#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub len: u32,         // packet length
    pub ctx_len: u32,     // skb length
    pub src_addr: u32,    // ipv4 source IP address
    pub dest_addr: u32,   // ipv4 destination IP address
    pub eth_proto: u32,   // Ethernet protocol
    pub eth_proto2: u32,  // skb->protocol, same as above
    pub ip_proto: u32,    // ipv4 protocol
    pub remote_port: u32, // TCP or UDP remote port (sport for ingress)
    pub remote_port2: u32,
    pub local_port: u32, // TCP or UDP local port (dport for ingress)
    pub local_port2: u32,
    pub udp_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
