#![no_std]
#![no_main]

use aya_bpf::{
    BpfContext,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_bpf::bindings:: __sk_buff;
use aya_bpf::helpers::bpf_skb_pull_data;
use core::mem;
use memoffset::offset_of;

use tcbpftest_common::PacketLog;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr, tcphdr, udphdr};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier(name="tcbpftest")]
pub fn tcbpftest(ctx: TcContext) -> i32 {
    match unsafe { try_tcbpftest(ctx) } {
        Ok(ret) => ret,
        Err(_) => 123,
    }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const IPPROTO_TCP : u8  = 6;
const IPPROTO_UDP : u8 = 17;

unsafe fn try_tcbpftest(ctx: TcContext) -> Result<i32, i64> {
    let ctx_len = ctx.len();
    let skb = ctx.as_ptr() as *mut __sk_buff;
    if  bpf_skb_pull_data(skb, ctx_len) != 0 {
        return Err(199);
    }
    // get the ethernet header proto field as well as the IP protocol one
    let eth_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto))?);
    let eth_proto2 = u32::from_be((*skb).protocol);
    let ip_proto = ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
    if !(eth_proto == ETH_P_IP && (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP)) {
        return Ok(0);
    }

    let length = u16::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, tot_len))?);
    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);
    let rem_port2 = u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?);
    let loc_port2 = u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?);

    let rem_port_val : u16;
    let loc_port_val : u16;
    unsafe {
      rem_port_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source)) {
            Err(_) => return Err(197),
            Ok(val) => *val,
      };
      loc_port_val =  match  ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest)) {
                Err(_) => return Err(198),
                Ok(val) => *val,
            };
    }
    let rem_port = u16::from_be(rem_port_val);
    let loc_port = u16::from_be(loc_port_val);

    let mut udp_len_val : u16 = 0;
    if ip_proto == IPPROTO_UDP {
      unsafe {
        udp_len_val = match ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, len)) {
            Err(_) => return Err(197),
            Ok(val) => *val,
        };
      }
    }
    let log_entry = PacketLog {
        len: length as u32,
        ctx_len: ctx_len,
        src_addr: saddr,
        dest_addr: daddr,
	    eth_proto: eth_proto as u32,
	    eth_proto2: eth_proto2 as u32,
        ip_proto: ip_proto as u32,
        remote_port: rem_port as u32,
        remote_port2: rem_port2 as u32,
        local_port: loc_port as u32,
        local_port2: loc_port2 as u32,
        udp_len: u16::from_be(udp_len_val) as u32,
    };

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(0)
}

// TODO: add en example with using the bpf_skb_pull_data helper and then ptr_at
//
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let raw_skb  = ctx.as_ptr() as *const __sk_buff;
    let start = (*raw_skb).data as usize;
    let end = (*raw_skb).data_end as usize;
    let len = mem::size_of::<T>();

    if start + offset  + len  > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
