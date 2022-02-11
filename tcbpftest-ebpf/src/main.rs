#![no_std]
#![no_main]

use aya_bpf::{
    BpfContext,
    macros::{map, classifier},
    maps::PerfEventArray,
    programs::SkBuffContext,
};
use aya_bpf::bindings:: __sk_buff;
use aya_bpf::helpers::bpf_skb_pull_data;
use core::mem;
use memoffset::offset_of;

use tcbpftest_common::PacketLog;

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier(name="tcbpftest")]
pub fn tcbpftest(ctx: SkBuffContext) -> i32 {
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
const SPORT_OFFSET : u8 = 0;
const DPORT_OFFSET : u8 = 0;

unsafe fn try_tcbpftest(ctx: SkBuffContext) -> Result<i32, i64> {
    // get the ethernet header proto field as well as the IP protocol one
    let eth_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto))?);
    let ip_proto = ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
    if !(eth_proto == ETH_P_IP && (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP)) {
        return Ok(0);
    }

    let length = u16::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, tot_len))?);
    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);
    let rem_port2 = u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?);
    let loc_port2 = u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?);

    let skb = ctx.as_ptr() as *mut __sk_buff;
    let ctx_len = ctx.len();
    if  bpf_skb_pull_data(skb, ctx_len) != 0 {
        return Err(199);
    }
    let rem_port_val : u32;
    let loc_port_val : u32;
    unsafe {
      loc_port_val =  match  ptr_at(&ctx, offset_of!(__sk_buff, local_port)) {
                Err(_) => return Err(198),
                Ok(val) => *val,
            };
      rem_port_val = match ptr_at(&ctx, offset_of!(__sk_buff, remote_port)) {
            Err(_) => return Err(197),
            Ok(val) => *val,
      };
    }
    let rem_port = u32::from_be(rem_port_val);
    let loc_port = u32::from_be(loc_port_val);

    let log_entry = PacketLog {
        len: length as u32,
        ctx_len: ctx_len,
        src_addr: saddr,
        dest_addr: daddr,
        proto: ip_proto as u32,
        remote_port: rem_port, //  as u32,
        remote_port2: rem_port2 as u32,
        local_port: loc_port, //  as u32,
        local_port2: loc_port2 as u32,
    };

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(0)
}

// TODO: add en example with using the bpf_skb_pull_data helper and then ptr_at
//
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &SkBuffContext, offset: usize) -> Result<*const T, ()> {
    let raw_skb  = ctx.as_ptr() as *const __sk_buff;
    let start = (*raw_skb).data as usize;
    let end = (*raw_skb).data_end as usize;
    let len = mem::size_of::<T>();

    if start + offset  + len  > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
