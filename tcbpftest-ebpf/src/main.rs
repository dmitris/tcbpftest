#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::IpProto,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

use tcbpftest_common::PacketLog;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier]
pub fn foobartest(ctx: TcContext) -> i32 {
    match unsafe { try_tcbpftest(ctx) } {
        Ok(ret) => ret,
        Err(_) => 123,
    }
}

unsafe fn try_tcbpftest(ctx: TcContext) -> Result<i32, i64> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| -1)?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN) }.map_err(|_| -1)?;
    let saddr = u32::from_be(unsafe { *ipv4hdr }.src_addr);
    let daddr = u32::from_be(unsafe { *ipv4hdr }.dst_addr);

    let mut udp_len_val: u16 = 0;
    let sport: u16;
    let dport: u16;
    match unsafe { *ipv4hdr }.proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;
            // let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1)?;

            // pass unless the SYN flag is set and ACK - not set
            if unsafe { *tcphdr }.syn() == 0 || unsafe { *tcphdr }.ack() != 0 {
                return Ok(TC_ACT_PIPE);
            }
            sport = u16::from_be(unsafe { *tcphdr }.source);
            dport = u16::from_be(unsafe { *tcphdr }.dest);
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }.map_err(|_| -1)?;
            // let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1)?;
            sport = u16::from_be(unsafe { *udphdr }.source);
            dport = u16::from_be(unsafe { *udphdr }.dest);
            udp_len_val = unsafe { *udphdr }.len;
        }
        _ => return Ok(TC_ACT_PIPE),
    };
    let log_entry = PacketLog {
        len: u16::from_be(unsafe { *ipv4hdr }.tot_len) as u32,
        ctx_len: ctx.len(),
        src_addr: saddr,
        dest_addr: daddr,
        eth_proto: u16::from_be(ethhdr.ether_type as u16) as u32,
        ip_proto: unsafe { *ipv4hdr }.proto as u32,
        sport: sport as u32,
        dport: dport as u32,
        udp_len: u16::from_be(udp_len_val) as u32,
    };

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(TC_ACT_PIPE)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// TODO: add en example with using the bpf_skb_pull_data helper and then ptr_at
//
// use aya_bpf::helpers::bpf_skb_pull_data;
//
// mod bindings;
// use bindings::{ethhdr, iphdr, tcphdr, udphdr};
//
// const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
// const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
//
// let ctx_len = ctx.len();
// let skb = ctx.as_ptr() as *mut __sk_buff;
// if bpf_skb_pull_data(skb, ctx_len) != 0 {
//     return Err(199);
// }
// get the ethernet header proto field as well as the IP protocol one
// let eth_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto))?);
// let eth_proto2 = u32::from_be((*skb).protocol);
// let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| -1)?;
// let ip_proto = ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
// let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
// let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);
// let rem_port_val: u16;
// let loc_port_val: u16;
// unsafe {
//     rem_port_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source)) {
//         Err(_) => return Err(197),
//         Ok(val) => *val,
//     };
//     loc_port_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest)) {
//         Err(_) => return Err(198),
//         Ok(val) => *val,
//     };
// }
// let rem_port = u16::from_be(rem_port_val);
// let loc_port = u16::from_be(loc_port_val);

// let mut udp_len_val: u16 = 0;
// if ipv4hdr.proto == IpProto::Udp {
//     unsafe {
//         udp_len_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, len)) {
//             Err(_) => return Err(197),
//             Ok(val) => *val,
//         };
//     }
// }
// let rem_port_val: u16;
// let loc_port_val: u16;
// unsafe {
//     rem_port_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source)) {
//         Err(_) => return Err(197),
//         Ok(val) => *val,
//     };
//     loc_port_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest)) {
//         Err(_) => return Err(198),
//         Ok(val) => *val,
//     };
// }
// let rem_port = u16::from_be(rem_port_val);
// let loc_port = u16::from_be(loc_port_val);}
