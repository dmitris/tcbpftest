#![no_std]
#![no_main]

use aya_bpf::{
    BpfContext,
    macros::{map, classifier},
    maps::PerfEventArray,
    programs::SkBuffContext,
};
use aya_bpf::bindings::__sk_buff;

use core::convert::TryInto;
use core::mem;
use memoffset::offset_of;

use tcbpftest_common::PacketLog;

mod bindings;
use bindings::{ethhdr, iphdr};

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

// #[inline(always)]
// unsafe fn ptr_at<T>(ctx: &SkBuffContext, offset: usize) -> Result<*const T, ()> {
//    let raw_skb  = ctx.as_ptr() as *const __sk_buff;
//    let start = (*raw_skb).data as usize;
//    let end = (*raw_skb).data_end as usize;
//   let len = mem::size_of::<T>();
//
//   if start + offset  + len  > end {
//       return Err(());
//   }
//
//   Ok((start + offset) as *const T)
// }
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IPPROTO_TCP : u8  = 6;
const IPPROTO_UDP : u8 = 17;

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
    let raw_skb  = ctx.as_ptr() as *const __sk_buff;
    let remote_port : u16 = u16::from_be((*raw_skb).remote_port);
    let local_port : u16 = u16::from_be((*raw_skb).local_port);
    let log_entry = PacketLog {
        len: length as u32,
        src_addr: saddr,
        dest_addr: daddr,
        remote_port: remote_port,
        local_port: local_port,
    };

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(0)
}
